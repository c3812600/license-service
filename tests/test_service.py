import base64
import datetime as dt
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from license_service import create_app
from license_service.config import Config, _allowed_app_names
from license_service.crypto import TOKEN_PREFIXES, ensure_keypair
from license_service.device_auth import _signed_message, decode_public_key


class LicenseServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db = root / "licenses.db"
        self.private = root / "private.pem"
        self.public = root / "public.pem"
        self.config_patch = patch.multiple(
            Config,
            ADMIN_TOKEN="test-admin",
            MACHINE_CODE_SALT="test-salt",
            DATABASE_PATH=str(self.db),
            PRIVATE_KEY_PATH=str(self.private),
            PUBLIC_KEY_PATH=str(self.public),
            TRIAL_DAYS=30,
            TRIAL_DAYS_MAP={"ControlCommand": 90},
            ALLOWED_APP_NAMES=("ControlCommand",),
        )
        self.config_patch.start()
        self.app = create_app()
        self.client = self.app.test_client()
        self.device_keys = {}

    def tearDown(self):
        self.config_patch.stop()
        self.temp.cleanup()

    def device_proof(self, action, machine="A" * 64, app_name="ControlCommand", key=None, client=None):
        client = client or self.client
        key = key or self.device_keys.setdefault(machine, Ed25519PrivateKey.generate())
        result = client.post(
            "/api/v1/devices/challenge",
            json={"app_name": app_name, "machine_code": machine, "action": action},
        )
        self.assertEqual(result.status_code, 200)
        challenge = result.json["data"]["challenge"]
        message = f"license-service/device/v1\n{action}\n{app_name}\n{machine}\n{challenge}".encode()
        public_key = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "app_name": app_name, "machine_code": machine, "challenge": challenge,
            "signature": base64.urlsafe_b64encode(key.sign(message)).rstrip(b"=").decode(),
            "device_public_key": base64.urlsafe_b64encode(public_key).rstrip(b"=").decode(),
        }

    def apply_trial(self, machine="A" * 64, days=365, app_name="ControlCommand", client=None):
        client = client or self.client
        proof = self.device_proof("trial", machine, app_name, client=client)
        return client.post(
            "/api/v1/trial/apply",
            json={**proof, "trial_days": days},
        )

    def test_trial_cap_retry_and_signature(self):
        first = self.apply_trial(days=365)
        self.assertEqual(first.status_code, 200)
        data = first.json["data"]
        self.assertEqual(data["trial_days"], 90)
        self.assertEqual(
            data["expires_at"],
            (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=90)).isoformat(),
        )
        prefix, encoded, signature = data["license_key"].split(".")
        self.assertEqual(prefix, "RCC1")
        public_key = serialization.load_pem_public_key(self.public.read_bytes())
        payload_bytes = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        public_key.verify(
            base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), payload_bytes
        )
        self.assertEqual(json.loads(payload_bytes)["machine_code"], "A" * 64)
        retry = self.apply_trial(days=1)
        self.assertEqual(retry.json["data"]["expires_at"], data["expires_at"])
        self.assertEqual(retry.json["data"]["trial_days"], 90)

    def test_expired_trial_cannot_restart(self):
        self.apply_trial()
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE license_issues SET expires_at='2020-01-01' WHERE channel='trial_auto'"
                )
        response = self.apply_trial()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json["error"], "trial expired")

    def test_invalid_days_use_cap_and_unregistered_app_is_rejected(self):
        response = self.apply_trial(machine="C" * 64, days=-5)
        self.assertEqual(response.json["data"]["trial_days"], 90)
        with patch.object(Config, "ALLOWED_APP_NAMES", ("NewApp",)):
            app = create_app()
            response = app.test_client().post(
                "/api/v1/trial/apply",
                json={"app_name": "NewApp", "machine_code": "D" * 64},
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "unsupported app_name")

    def test_default_allowed_apps_include_registered_products(self):
        with patch.dict(os.environ, {"LICENSE_SERVICE_ALLOWED_APPS": ""}):
            defaults = _allowed_app_names()
        self.assertEqual(defaults, ("ControlCommand", "E-Player", "WinPilot", "iCMS", "rust-node"))
        for app_name in ("iCMS", "rust-node"):
            with self.subTest(app_name=app_name), patch.object(Config, "ALLOWED_APP_NAMES", defaults):
                response = self.apply_trial(machine="E" * 64, app_name=app_name, client=create_app().test_client())
                self.assertEqual(response.status_code, 200)
                self.assertTrue(
                    response.json["data"]["license_key"].startswith(TOKEN_PREFIXES[app_name] + ".")
                )

    def test_failed_trial_issue_rolls_back_and_releases_lock(self):
        from license_service import service

        original_issue = service._issue_record

        def fail_after_insert(*args, **kwargs):
            original_issue(*args, **kwargs)
            raise RuntimeError("simulated failure after insert")

        with patch.object(service, "_issue_record", side_effect=fail_after_insert):
            response = self.apply_trial(machine="F" * 64)
        self.assertEqual(response.status_code, 409)
        with closing(sqlite3.connect(self.db, timeout=1)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM license_issues").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0], 0)
        self.assertEqual(self.apply_trial(machine="F" * 64).status_code, 200)

    def test_concurrent_claims_keep_original_deadline(self):
        self.device_keys["B" * 64] = Ed25519PrivateKey.generate()

        def claim(_):
            with self.app.test_client() as client:
                return self.apply_trial(machine="B" * 64, days=20, client=client)

        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(pool.map(claim, range(6)))
        self.assertTrue(all(r.status_code == 200 for r in responses))
        self.assertEqual(len({r.json["data"]["expires_at"] for r in responses}), 1)
        with closing(sqlite3.connect(self.db)) as conn:
            count = conn.execute(
                "SELECT COUNT(DISTINCT expires_at) FROM license_issues WHERE channel='trial_auto'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_keypair_must_not_be_replaced(self):
        original = self.private.read_bytes()
        self.public.unlink()
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            ensure_keypair(self.private, self.public)
        self.assertEqual(self.private.read_bytes(), original)
        self.assertFalse(self.public.exists())

    def test_existing_keypair_skips_generation_on_restart(self):
        private_before = self.private.read_bytes()
        public_before = self.public.read_bytes()
        with patch("license_service.crypto.Ed25519PrivateKey.generate", side_effect=AssertionError("regenerated")):
            create_app()
        self.assertEqual(self.private.read_bytes(), private_before)
        self.assertEqual(self.public.read_bytes(), public_before)

    def test_mismatched_keypair_rejected(self):
        other_private = Path(self.temp.name) / "other-private.pem"
        other_public = Path(self.temp.name) / "other-public.pem"
        ensure_keypair(other_private, other_public)
        self.public.write_bytes(other_public.read_bytes())
        with self.assertRaisesRegex(RuntimeError, "do not match"):
            ensure_keypair(self.private, self.public)

    def test_existing_database_requires_original_keys(self):
        self.private.unlink()
        self.public.unlink()
        with self.assertRaisesRegex(RuntimeError, "restore"):
            create_app()
        self.assertFalse(self.private.exists())

    def test_admin_stats_and_auth(self):
        self.assertEqual(self.client.get("/admin/stats").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/stats").status_code, 401)
        self.apply_trial()
        response = self.client.get("/api/v1/stats", headers={"X-Admin-Token": "test-admin"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"]["overview"]["total"], 1)
        self.assertNotIn("license_token", json.dumps(response.json))
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(
            self.client.post(
                "/api/v1/licenses/renew",
                json={"app_name": "ControlCommand", "machine_code": "A" * 64, "expires_at": "2030-01-01"},
            ).status_code,
            401,
        )

    def test_stats_named_date_binding_counts_expired_status(self):
        self.apply_trial(machine="A" * 64)
        self.apply_trial(machine="B" * 64)
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE license_issues SET expires_at='2020-01-01' WHERE machine_code_last4='BBBB'"
                )
        response = self.client.get("/api/v1/stats", headers={"X-Admin-Token": "test-admin"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {item["status"]: item["count"] for item in response.json["data"]["status_distribution"]},
            {"active": 1, "expired": 1},
        )

    def test_stats_skip_malformed_issued_at(self):
        self.apply_trial(machine="A" * 64)
        self.apply_trial(machine="B" * 64)
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE license_issues SET issued_at='x' WHERE machine_code_last4='BBBB'"
                )
        response = self.client.get("/api/v1/stats", headers={"X-Admin-Token": "test-admin"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"]["overview"]["total"], 2)
        self.assertEqual(
            response.json["data"]["monthly_trend"],
            [{"month": dt.date.today().strftime("%Y-%m"), "count": 1}],
        )

    def test_stats_does_not_fetch_entire_issue_table(self):
        self.apply_trial()
        with patch("license_service.service.fetch_all", side_effect=AssertionError("full-table fetch")):
            response = self.client.get("/api/v1/stats", headers={"X-Admin-Token": "test-admin"})
        self.assertEqual(response.status_code, 200)

    def test_stats_aggregate_all_records_but_limit_details(self):
        for number in range(25):
            self.assertEqual(self.apply_trial(machine=f"{number:064X}", days=1).status_code, 200)
        response = self.client.get("/api/v1/stats", headers={"X-Admin-Token": "test-admin"})
        data = response.json["data"]
        self.assertEqual(data["overview"]["total"], 25)
        self.assertEqual(data["overview"]["unique_machines"], 25)
        self.assertEqual(data["overview"]["expiring_30d"], 25)
        self.assertEqual(len(data["recent_issues"]), 20)
        self.assertEqual(len(data["expiring_soon"]), 20)
        self.assertEqual(data["monthly_trend"][0]["count"], 25)

    def test_latest_requires_fresh_device_signature(self):
        issued = self.apply_trial().json["data"]
        self.assertEqual(self.client.get("/api/v1/licenses/latest").status_code, 405)
        unsigned = self.client.post(
            "/api/v1/licenses/latest", json={"app_name": "ControlCommand", "machine_code": "A" * 64}
        )
        self.assertNotEqual(unsigned.status_code, 200)
        proof = self.device_proof("latest")
        response = self.client.post("/api/v1/licenses/latest", json=proof)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"]["license_key"], issued["license_key"])
        self.assertEqual(self.client.post("/api/v1/licenses/latest", json=proof).status_code, 403)

    def test_latest_rejects_wrong_device_purpose_and_expired_challenge(self):
        self.apply_trial()
        proof = self.device_proof("latest")
        wrong_key = Ed25519PrivateKey.generate()
        message = (
            f"license-service/device/v1\nlatest\nControlCommand\n{'A' * 64}\n{proof['challenge']}"
        ).encode()
        wrong_signature = base64.urlsafe_b64encode(wrong_key.sign(message)).rstrip(b"=").decode()
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json={**proof, "signature": wrong_signature}).status_code,
            403,
        )
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json={**proof, "machine_code": "B" * 64}).status_code,
            403,
        )
        trial_proof = self.device_proof("trial")
        self.assertEqual(self.client.post("/api/v1/licenses/latest", json=trial_proof).status_code, 403)
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE device_challenges SET expires_at=0 WHERE challenge=?", (proof["challenge"],)
                )
        self.assertEqual(self.client.post("/api/v1/licenses/latest", json=proof).status_code, 403)

    def test_latest_excludes_expired_revoked_and_offline_issues(self):
        self.apply_trial()
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute("UPDATE license_issues SET expires_at='2020-01-01'")
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest")).status_code, 404
        )
        offline = self.client.post(
            "/api/v1/licenses/offline-issue", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": "A" * 64, "expires_at": "2040-01-01"},
        )
        self.assertEqual(offline.status_code, 200)
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest")).status_code, 404
        )
        paid = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": "A" * 64, "expires_at": "2030-01-01"},
        )
        self.assertEqual(paid.status_code, 200)
        picked = self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest"))
        self.assertEqual(picked.json["data"]["license_key"], paid.json["data"]["license_key"])
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE license_issues SET status='revoked' WHERE issue_id=?",
                    (paid.json["data"]["issue_id"],),
                )
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest")).status_code, 404
        )

    def test_paid_device_requires_admin_enrollment_and_can_rotate_or_revoke(self):
        machine = "D" * 64
        paid = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": "2030-01-01"},
        )
        self.assertEqual(paid.status_code, 200)
        self.assertEqual(self.apply_trial(machine=machine).status_code, 409)
        enrollment = self.device_proof("register", machine=machine)
        self.assertEqual(self.client.post("/api/v1/devices/register", json=enrollment).status_code, 401)
        self.assertEqual(self.client.post(
            "/api/v1/devices/register", json=enrollment, headers={"X-Admin-Token": "test-admin"}
        ).status_code, 200)
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest", machine=machine)).status_code,
            200,
        )
        new_key = Ed25519PrivateKey.generate()
        new_enrollment = self.device_proof("register", machine=machine, key=new_key)
        self.assertEqual(self.client.post(
            "/api/v1/devices/register", json=new_enrollment, headers={"X-Admin-Token": "test-admin"}
        ).status_code, 200)
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest", machine=machine)).status_code,
            403,
        )
        self.device_keys[machine] = new_key
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest", machine=machine)).status_code,
            200,
        )
        self.assertEqual(self.client.post(
            "/api/v1/devices/revoke",
            json={"app_name": "ControlCommand", "machine_code": machine},
            headers={"X-Admin-Token": "test-admin"},
        ).status_code, 200)
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest", machine=machine)).status_code,
            403,
        )

    def test_trial_rejects_reenrollment_with_different_key(self):
        first = self.apply_trial()
        self.assertEqual(first.status_code, 200)
        other_key = Ed25519PrivateKey.generate()
        proof = self.device_proof("trial", key=other_key)
        self.assertEqual(self.client.post("/api/v1/trial/apply", json=proof).status_code, 403)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM license_issues").fetchone()[0], 1)

    def test_legacy_trial_requires_admin_enrollment_without_resetting_deadline(self):
        from license_service.service import _issue_record

        original_deadline = "2030-01-01"
        _issue_record(
            self.app, app_name="ControlCommand", machine_code="A" * 64,
            license_type="trial", expires_at=original_deadline, channel="trial_auto",
        )
        self.assertEqual(self.apply_trial().status_code, 409)
        enrollment = self.device_proof("register")
        challenge = self.client.post(
            "/api/v1/devices/challenge",
            json={"app_name": "ControlCommand", "machine_code": "A" * 64, "action": "register"},
        )
        self.assertEqual(challenge.json["data"]["expires_in"], 900)
        self.assertEqual(self.client.post(
            "/api/v1/devices/register", json=enrollment, headers={"X-Admin-Token": "test-admin"}
        ).status_code, 200)
        self.assertEqual(self.apply_trial().json["data"]["expires_at"], original_deadline)

    def test_trial_requires_strong_machine_code_and_valid_proof(self):
        weak = self.device_proof("trial", machine="ABCDEF12")
        self.assertEqual(self.client.post("/api/v1/trial/apply", json=weak).status_code, 400)
        self.assertEqual(self.client.post(
            "/api/v1/trial/apply", json={"app_name": [], "machine_code": []}
        ).status_code, 400)
        proof = self.device_proof("trial")
        self.assertEqual(
            self.client.post("/api/v1/trial/apply", json={**proof, "signature": "invalid"}).status_code,
            400,
        )
        self.assertEqual(self.client.post("/api/v1/trial/apply", json=proof).status_code, 200)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0], 1)

    def test_challenge_rejects_non_string_action(self):
        for action in ([], {}, 12):
            with self.subTest(action=action):
                response = self.client.post(
                    "/api/v1/devices/challenge",
                    json={"app_name": "ControlCommand", "machine_code": "A" * 64, "action": action},
                )
                self.assertEqual(response.status_code, 400)

    def test_competing_device_keys_cannot_both_claim_first_trial(self):
        proofs = [
            self.device_proof("trial", machine="C" * 64, key=Ed25519PrivateKey.generate())
            for _ in range(2)
        ]

        def claim(proof):
            with self.app.test_client() as client:
                return client.post("/api/v1/trial/apply", json=proof).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(claim, proofs))
        self.assertEqual(sorted(statuses), [200, 403])
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM license_issues").fetchone()[0], 1)

    def test_device_signature_cross_language_vector(self):
        seed = bytes(range(32))
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = base64.urlsafe_b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )).rstrip(b"=").decode()
        message = _signed_message("latest", "ControlCommand", "A" * 64, "A" * 43)
        signature = base64.urlsafe_b64encode(key.sign(message)).rstrip(b"=").decode()
        self.assertEqual(len(message), 156)
        self.assertEqual(public_key, "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg")
        self.assertEqual(
            signature,
            "HNhvGmg8ez2IrCEP2uypAGDkMHOmGsribExv25ujZSZ5zRIxKdfLucahMQRhufmCdjcWFRJxd1Ljvu2KKUIeAw",
        )
        self.assertEqual(len(decode_public_key(public_key)), 32)


if __name__ == "__main__":
    unittest.main()
