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
            RATE_LIMIT_ENABLED=False,
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
                    "UPDATE device_challenges SET expires_at_epoch=0 WHERE challenge=?", (proof["challenge"],)
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

    def test_paid_machine_cannot_self_service_trial(self):
        # P0-2: 已有付费授权的机器不能自助领试用（防止试用顶替付费）
        machine = "E" * 64
        paid = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": "2030-01-01"},
        )
        self.assertEqual(paid.status_code, 200)
        enroll = self.device_proof("register", machine=machine)
        self.assertEqual(
            self.client.post("/api/v1/devices/register", json=enroll, headers={"X-Admin-Token": "test-admin"}).status_code,
            200,
        )
        self.assertEqual(self.apply_trial(machine=machine).status_code, 403)

    def test_latest_prefers_paid_over_trial(self):
        # P0-3: latest 取数按 license_type 优先级，试用不得顶掉付费
        machine = "C" * 64
        trial = self.apply_trial(machine=machine, days=30)
        self.assertEqual(trial.status_code, 200)
        paid = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": "2026-11-20"},
        )
        self.assertEqual(paid.status_code, 200)
        picked = self.client.post("/api/v1/licenses/latest", json=self.device_proof("latest", machine=machine))
        self.assertEqual(picked.status_code, 200)
        self.assertEqual(picked.json["data"]["license_key"], paid.json["data"]["license_key"])

    def test_admin_forget_then_retry_trial(self):
        machine = "F" * 64
        self.assertEqual(self.apply_trial(machine=machine).status_code, 200)
        res = self.client.post(
            "/api/v1/devices/forget", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine},
        )
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(res.json["data"]["removed_issues"], 1)
        # 记录清空后，机器可当"全新"重领试用
        self.assertEqual(self.apply_trial(machine=machine).status_code, 200)

    def test_admin_list_devices_and_summary_stable_under_search(self):
        machine = "1" * 64
        self.assertEqual(self.apply_trial(machine=machine).status_code, 200)
        full = self.client.get("/api/v1/devices", headers={"X-Admin-Token": "test-admin"})
        self.assertEqual(full.status_code, 200)
        self.assertEqual(full.json["data"]["summary"]["total"], 1)
        # 搜索只影响展示，不影响统计（summary 独立于 q）
        filtered = self.client.get("/api/v1/devices?q=zzz_no_match", headers={"X-Admin-Token": "test-admin"})
        self.assertEqual(filtered.json["data"]["devices"], [])
        self.assertEqual(filtered.json["data"]["summary"]["total"], 1)

    def test_admin_update_device_meta(self):
        machine = "2" * 64
        self.assertEqual(self.apply_trial(machine=machine).status_code, 200)
        res = self.client.patch(
            "/api/v1/devices", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "customer_name": "ACME", "notes": "测试备注"},
        )
        self.assertEqual(res.status_code, 200)
        lst = self.client.get("/api/v1/devices", headers={"X-Admin-Token": "test-admin"})
        dev = [d for d in lst.json["data"]["devices"] if d["machine_code"] == machine][0]
        self.assertEqual(dev["customer_name"], "ACME")
        self.assertEqual(dev["notes"], "测试备注")

    def test_admin_active_key(self):
        machine = "3" * 64
        issued = self.apply_trial(machine=machine).json["data"]
        res = self.client.get(
            "/api/v1/licenses/active_key?app_name=ControlCommand&machine_code=" + machine,
            headers={"X-Admin-Token": "test-admin"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json["data"]["license_key"], issued["license_key"])

    def test_supersede_failure_rolls_back_and_keeps_old_license(self):
        """体检 P0-3 回归：吊销+签发单事务，签发失败整体回滚、旧授权不掉。"""
        machine = "F" * 64
        first = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": "2030-01-01"},
        )
        self.assertEqual(first.status_code, 200)
        with patch("license_service.service._issue_record", side_effect=OSError("disk full")):
            failed = self.client.post(
                "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
                json={
                    "app_name": "ControlCommand", "machine_code": machine,
                    "expires_at": "2031-01-01", "supersede": True,
                },
            )
        self.assertEqual(failed.status_code, 500)
        self.assertFalse(failed.json.get("ok", True))
        with closing(sqlite3.connect(self.db)) as conn:
            rows = conn.execute(
                "SELECT status, expires_at FROM license_issues ORDER BY id"
            ).fetchall()
        # 回滚后：只有最初那条付费授权，仍 active 且原到期日
        self.assertEqual([(r[0], r[1]) for r in rows], [("active", "2030-01-01")])

    def test_rate_limit_returns_429(self):
        """体检 P1-4 配套：内置限流按 (IP,路径) 计数，超限返回 429。"""
        from license_service import _RATE_HITS

        _RATE_HITS.clear()
        self.app.config["RATE_LIMIT_ENABLED"] = True
        try:
            codes = [
                self.client.post("/api/v1/trial/apply", json={}).status_code
                for _ in range(6)
            ]
        finally:
            self.app.config["RATE_LIMIT_ENABLED"] = False
            _RATE_HITS.clear()
        self.assertEqual(codes[:5], [400] * 5)  # 前 5 个走业务校验（缺 app_name）
        self.assertEqual(codes[5], 429)

    def test_rotation_with_license_key_heals_key_drift(self):
        """持证换钥主路径：持有效授权码自动换绑新公钥，旧钥失效、新钥可拾取。"""
        machine = "9" * 64
        old_key = Ed25519PrivateKey.generate()
        new_key = Ed25519PrivateKey.generate()
        paid = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": "2030-01-01"},
        )
        self.assertEqual(paid.status_code, 200)
        license_key = paid.json["data"]["license_key"]
        self.assertEqual(
            self.client.post(
                "/api/v1/devices/register",
                json=self.device_proof("register", machine=machine, key=old_key),
                headers={"X-Admin-Token": "test-admin"},
            ).status_code, 200,
        )
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest",
                             json=self.device_proof("latest", machine=machine, key=old_key)).status_code, 200,
        )
        # 密钥漂移：新钥 + license_key 持证换钥（不带管理令牌）
        rotate = self.device_proof("register", machine=machine, key=new_key)
        rotate["license_key"] = license_key
        self.assertEqual(self.client.post("/api/v1/devices/register", json=rotate).status_code, 200)
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest",
                             json=self.device_proof("latest", machine=machine, key=new_key)).status_code, 200,
        )
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest",
                             json=self.device_proof("latest", machine=machine, key=old_key)).status_code, 403,
        )

    def test_rotation_rejects_bad_tokens_and_revoked_devices(self):
        """持证换钥闸门：错机器/过期/伪造授权码拒；吊销不因换绑复活。"""
        machine = "7" * 64
        key = Ed25519PrivateKey.generate()
        paid = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": "2030-01-01"},
        )
        license_key = paid.json["data"]["license_key"]

        def rotate(tok):
            proof = self.device_proof("register", machine=machine, key=key)
            proof["license_key"] = tok
            return self.client.post("/api/v1/devices/register", json=proof)

        # 另一台机器的授权码 → 机器不匹配
        other = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": "B" * 64, "expires_at": "2030-01-01"},
        ).json["data"]["license_key"]
        self.assertEqual(rotate(other).status_code, 403)
        # 过期授权码 → 拒
        expired = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": "2020-01-01"},
        ).json["data"]["license_key"]
        self.assertEqual(rotate(expired).status_code, 403)
        # 篡改签名 → 拒
        broken = license_key[:-4] + ("AAAA" if not license_key.endswith("AAAA") else "BBBB")
        self.assertIn(rotate(broken).status_code, (400, 403))
        # 吊销后持证也不复活（revoke 语义保留）
        self.assertEqual(
            self.client.post("/api/v1/devices/register", json=self.device_proof("register", machine=machine, key=key),
                             headers={"X-Admin-Token": "test-admin"}).status_code, 200,
        )
        self.assertEqual(
            self.client.post("/api/v1/devices/revoke",
                             json={"app_name": "ControlCommand", "machine_code": machine},
                             headers={"X-Admin-Token": "test-admin"}).status_code, 200,
        )
        res = rotate(license_key)
        self.assertEqual(res.status_code, 403)
        self.assertIn("revoked", res.json["error"])

    def test_rotation_rate_limited_per_machine(self):
        """每机每日换绑 3 次硬限（audit_logs 计数），第 4 次拒。"""
        machine = "6" * 64
        paid = self.client.post(
            "/api/v1/licenses/renew", headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": "2030-01-01"},
        )
        license_key = paid.json["data"]["license_key"]
        codes = []
        for _ in range(4):
            proof = self.device_proof("register", machine=machine, key=Ed25519PrivateKey.generate())
            proof["license_key"] = license_key
            codes.append(self.client.post("/api/v1/devices/register", json=proof).status_code)
        self.assertEqual(codes[:3], [200, 200, 200])
        self.assertEqual(codes[3], 403)

    # ---- 激活码 / 在线校验 / 解绑 ----

    def _issue_codes(self, **overrides):
        payload = {"app_name": "ControlCommand", "days": 30, "count": 2}
        payload.update(overrides)
        return self.client.post(
            "/api/v1/activation-codes", json=payload,
            headers={"X-Admin-Token": "test-admin"},
        )

    def test_activation_code_lifecycle(self):
        created = self._issue_codes(days=30, count=2)
        self.assertEqual(created.status_code, 200, created.json)
        codes = created.json["data"]["codes"]
        self.assertEqual(len(codes), 2)
        for code in codes:
            self.assertRegex(code, r"^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$")

        machine = "7" * 64
        proof = self.device_proof("activate", machine=machine)
        first = self.client.post(
            "/api/v1/activate", json={**proof, "code": codes[0], "app_version": "1.0.0"}
        )
        self.assertEqual(first.status_code, 200, first.json)
        data = first.json["data"]
        self.assertEqual(data["license_key"].split(".")[0], "RCC1")
        self.assertEqual(
            data["expires_at"],
            (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30)).isoformat(),
        )
        self.assertEqual(data["channel"], "activation_code")

        # 兑换即登记设备：随后可正常 validate
        validate_proof = self.device_proof("validate", machine=machine)
        checked = self.client.post(
            "/api/v1/validate", json={**validate_proof, "license_token": data["license_key"]}
        )
        self.assertEqual(checked.status_code, 200, checked.json)
        self.assertEqual(checked.json["data"]["status"], "active")

        again = self.client.post(
            "/api/v1/activate",
            json={**self.device_proof("activate", machine=machine), "code": codes[0].lower()},
        )
        self.assertEqual(again.status_code, 400)
        self.assertEqual(again.json["error"], "activation code already used")

        with closing(sqlite3.connect(self.db)) as conn:
            row = conn.execute(
                "SELECT status, issue_id FROM activation_codes WHERE code=?",
                (codes[0].replace("-", ""),),
            ).fetchone()
        self.assertEqual(row[0], "used")
        self.assertEqual(row[1], data["issue_id"])

    def test_activation_code_rejects_bad_input(self):
        self.assertEqual(
            self.client.post(
                "/api/v1/activation-codes", json={"app_name": "ControlCommand", "days": 30}
            ).status_code,
            401,
        )
        self.assertEqual(self._issue_codes(days=0).status_code, 400)
        self.assertEqual(self._issue_codes(count=101).status_code, 400)

        codes = self._issue_codes(days=30, count=1).json["data"]["codes"]
        machine = "8" * 64
        proof = self.device_proof("activate", machine=machine)
        bad_signature = {**proof, "signature": "A" * 86}
        self.assertEqual(
            self.client.post("/api/v1/activate", json={**bad_signature, "code": codes[0]}).status_code,
            403,
        )
        self.assertEqual(
            self.client.post("/api/v1/activate", json={**proof, "code": "not-a-code"}).status_code,
            400,
        )

        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute("UPDATE activation_codes SET expires_at='2020-01-01'")
        expired = self.client.post("/api/v1/activate", json={**proof, "code": codes[0]})
        self.assertEqual(expired.status_code, 400)
        self.assertEqual(expired.json["error"], "activation code expired")

    def test_activation_code_app_mismatch(self):
        codes = self._issue_codes(days=30, count=1).json["data"]["codes"]
        with patch.object(Config, "ALLOWED_APP_NAMES", ("ControlCommand", "E-Player")):
            app = create_app()
            client = app.test_client()
            proof = self.device_proof(
                "activate", machine="8" * 64, app_name="E-Player", client=client
            )
            result = client.post("/api/v1/activate", json={**proof, "code": codes[0]})
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.json["error"], "activation code app mismatch")

    def test_validate_reports_active_expired_and_revoked(self):
        machine = "9" * 64
        license_key = self.apply_trial(machine=machine).json["data"]["license_key"]

        def check():
            proof = self.device_proof("validate", machine=machine)
            return self.client.post("/api/v1/validate", json={**proof, "license_token": license_key})

        active = check()
        self.assertEqual(active.status_code, 200, active.json)
        self.assertEqual(active.json["data"]["status"], "active")
        self.assertTrue(active.json["data"]["server_time"].endswith("Z"))

        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute("UPDATE license_issues SET expires_at='2020-01-01'")
        self.assertEqual(check().json["data"]["status"], "expired")

        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute("UPDATE license_issues SET status='revoked'")
        self.assertEqual(check().json["data"]["status"], "revoked")

    def test_validate_rejects_unregistered_device_and_foreign_token(self):
        self.apply_trial(machine="A" * 64)
        unregistered = self.device_proof("validate", machine="B" * 64)
        rejected = self.client.post(
            "/api/v1/validate", json={**unregistered, "license_token": "X.y.z"}
        )
        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(rejected.json["error"], "device not enrolled or revoked")

        self.apply_trial(machine="B" * 64)
        foreign_key = self.apply_trial(machine="C" * 64).json["data"]["license_key"]
        proof = self.device_proof("validate", machine="B" * 64)
        mismatch = self.client.post(
            "/api/v1/validate", json={**proof, "license_token": foreign_key}
        )
        self.assertEqual(mismatch.status_code, 403)
        self.assertEqual(mismatch.json["error"], "license machine mismatch")

    def test_unbind_revokes_licenses_and_credential(self):
        machine = "D" * 64
        self.apply_trial(machine=machine)
        headers = {"X-Admin-Token": "test-admin"}

        self.assertEqual(
            self.client.post(
                "/api/v1/unbind", json={"app_name": "ControlCommand", "machine_code": machine}
            ).status_code,
            401,
        )

        first = self.client.post(
            "/api/v1/unbind",
            json={"app_name": "ControlCommand", "machine_code": machine},
            headers=headers,
        )
        self.assertEqual(first.status_code, 200, first.json)
        self.assertEqual(first.json["data"]["revoked_issues"], 1)
        self.assertTrue(first.json["data"]["credential_revoked"])

        proof = self.device_proof("latest", machine=machine)
        self.assertEqual(
            self.client.post("/api/v1/licenses/latest", json=proof).status_code, 403
        )

        second = self.client.post(
            "/api/v1/unbind",
            json={"app_name": "ControlCommand", "machine_code": machine},
            headers=headers,
        )
        self.assertEqual(second.json["data"]["revoked_issues"], 0)
        self.assertFalse(second.json["data"]["credential_revoked"])

    def test_untrusted_peer_proxy_headers_are_stripped(self):
        """体检 R2：非可信来源伪造 XFF 不被采纳；本机/容器网桥来源才信任。"""
        from license_service import _strip_untrusted_proxy_headers

        untrusted = {"REMOTE_ADDR": "10.0.0.50", "HTTP_X_FORWARDED_FOR": "1.2.3.4"}
        _strip_untrusted_proxy_headers(untrusted)
        self.assertNotIn("HTTP_X_FORWARDED_FOR", untrusted)
        for peer in ("127.0.0.1", "172.17.0.3"):
            env = {"REMOTE_ADDR": peer, "HTTP_X_FORWARDED_FOR": "1.2.3.4"}
            _strip_untrusted_proxy_headers(env)
            self.assertEqual(env.get("HTTP_X_FORWARDED_FOR"), "1.2.3.4")


    def test_error_envelope_always_carries_code(self):
        """契约：错误信封恒为 {ok:false,error,code}；成功响应不含 code。"""
        ok = self.client.get("/api/v1/health")
        self.assertEqual(ok.status_code, 200)
        self.assertNotIn("code", ok.json)
        self.assertNotIn("code", ok.json["data"])

        bad_json = self.client.post(
            "/api/v1/trial/apply", data='"x"', content_type="application/json"
        )
        self.assertEqual(bad_json.status_code, 400)
        self.assertEqual(bad_json.json["code"], "INVALID_INPUT")

        missing = self.client.post("/api/v1/trial/apply", json={})
        self.assertEqual(missing.json["code"], "INVALID_INPUT")

        wrong_admin = self.client.get(
            "/api/v1/stats", headers={"X-Admin-Token": "nope"}
        )
        self.assertEqual(wrong_admin.status_code, 401)
        self.assertEqual(wrong_admin.json["code"], "UNAUTHORIZED")

        legacy_get = self.client.get("/api/v1/licenses/latest")
        self.assertEqual(legacy_get.status_code, 405)
        self.assertEqual(legacy_get.json["code"], "METHOD_NOT_ALLOWED")

        empty_key = self.client.get(
            "/api/v1/licenses/active_key",
            query_string={"app_name": "ControlCommand", "machine_code": "A" * 64},
            headers={"X-Admin-Token": "test-admin"},
        )
        self.assertEqual(empty_key.status_code, 404)
        self.assertEqual(empty_key.json["code"], "NOT_FOUND")

        unknown_app = self.client.post(
            "/api/v1/devices/challenge",
            json={"app_name": "Nope", "machine_code": "A" * 64, "action": "trial"},
        )
        self.assertEqual(unknown_app.json["code"], "INVALID_INPUT")

        bad_date = self.client.post(
            "/api/v1/licenses/renew",
            headers={"X-Admin-Token": "test-admin"},
            json={
                "app_name": "ControlCommand", "machine_code": "A" * 64,
                "expires_at": "not-a-date",
            },
        )
        self.assertEqual(bad_date.status_code, 400)
        self.assertEqual(bad_date.json["code"], "INVALID_INPUT")

    def test_error_codes_branch_client_flows(self):
        """按 code 分流：文案不变，code 指明客户端该走哪条路。"""
        machine = "5" * 64
        headers = {"X-Admin-Token": "test-admin"}

        # 未登记设备领授权 → LICENSE_REQUIRED（文案沿用 device not enrolled or revoked）
        unenrolled = self.client.post(
            "/api/v1/licenses/latest",
            json=self.device_proof("latest", machine=machine),
        )
        self.assertEqual(unenrolled.status_code, 403)
        self.assertEqual(unenrolled.json["code"], "LICENSE_REQUIRED")

        # 伪签名 → SIGNATURE_INVALID
        proof = self.device_proof("latest", machine=machine)
        proof["signature"] = "A" * 86
        self.apply_trial(machine=machine)
        forged = self.client.post("/api/v1/licenses/latest", json=proof)
        self.assertEqual(forged.status_code, 403)
        self.assertEqual(forged.json["code"], "SIGNATURE_INVALID")

        # 挑战复用（一次性）→ CHALLENGE_INVALID
        consumed = self.device_proof("latest", machine=machine)
        self.client.post("/api/v1/licenses/latest", json=consumed)
        reused = self.client.post("/api/v1/licenses/latest", json=consumed)
        self.assertEqual(reused.status_code, 403)
        self.assertEqual(reused.json["code"], "CHALLENGE_INVALID")

        # 吊销设备 → REVOKED（文案仍为 device not enrolled or revoked）
        self.client.post(
            "/api/v1/devices/revoke",
            json={"app_name": "ControlCommand", "machine_code": machine},
            headers=headers,
        )
        revoked = self.client.post(
            "/api/v1/licenses/latest",
            json=self.device_proof("latest", machine=machine),
        )
        self.assertEqual(revoked.status_code, 403)
        self.assertEqual(revoked.json["code"], "REVOKED")

        # 他机 Token → MACHINE_MISMATCH
        other = "6" * 64
        foreign_key = self.apply_trial(machine=other).json["data"]["license_key"]
        mine = "7" * 64
        self.apply_trial(machine=mine)
        mismatch = self.client.post(
            "/api/v1/validate",
            json={**self.device_proof("validate", machine=mine), "license_token": foreign_key},
        )
        self.assertEqual(mismatch.status_code, 403)
        self.assertEqual(mismatch.json["code"], "MACHINE_MISMATCH")

        # 付费机器自领试用 → CONFLICT（已登记设备 + 已有付费授权）
        paid_machine = "8" * 64
        self.client.post(
            "/api/v1/licenses/renew",
            headers=headers,
            json={"app_name": "ControlCommand", "machine_code": paid_machine,
                  "expires_at": "2030-01-01"},
        )
        self.client.post(
            "/api/v1/devices/register",
            json=self.device_proof("register", machine=paid_machine),
            headers=headers,
        )
        conflict = self.apply_trial(machine=paid_machine)
        self.assertEqual(conflict.status_code, 403)
        self.assertEqual(conflict.json["code"], "CONFLICT")

        # 试用到期 → EXPIRED（409）
        expired_machine = "4" * 64
        self.apply_trial(machine=expired_machine)
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute("UPDATE license_issues SET expires_at='2020-01-01'")
        expired = self.apply_trial(machine=expired_machine)
        self.assertEqual(expired.status_code, 409)
        self.assertEqual(expired.json["code"], "EXPIRED")

        # 激活码：产品不符 → PRODUCT_MISMATCH；已用 → CONFLICT；码过期 → EXPIRED
        codes = self._issue_codes(days=30, count=1).json["data"]["codes"]
        wrong_app_machine = "3" * 64
        wrong_app_proof = self.device_proof(
            "activate", machine=wrong_app_machine, app_name="ControlCommand"
        )
        # 用其他产品的码（先造一张别的产品的码，但 Config 只放行 ControlCommand，
        # 这里直接改库把码挂到未授权产品名下，模拟串货）
        compact = codes[0].replace("-", "")
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE activation_codes SET app_name='E-Player' WHERE code=?", (compact,)
                )
        product_mismatch = self.client.post(
            "/api/v1/activate", json={**wrong_app_proof, "code": codes[0]}
        )
        self.assertEqual(product_mismatch.status_code, 400)
        self.assertEqual(product_mismatch.json["code"], "PRODUCT_MISMATCH")

        reused_code = self._issue_codes(days=30, count=1).json["data"]["codes"][0]
        machine_c = "2" * 64
        self.client.post(
            "/api/v1/activate",
            json={**self.device_proof("activate", machine=machine_c), "code": reused_code},
        )
        machine_d = "1" * 64
        used = self.client.post(
            "/api/v1/activate",
            json={**self.device_proof("activate", machine=machine_d), "code": reused_code.lower()},
        )
        self.assertEqual(used.status_code, 400)
        self.assertEqual(used.json["code"], "CONFLICT")

        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE activation_codes SET expires_at='2020-01-01' WHERE status='issued'"
                )
        fresh = self._issue_codes(days=30, count=1).json["data"]["codes"][0]
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE activation_codes SET expires_at='2020-01-01' WHERE code=?",
                    (fresh.replace("-", ""),),
                )
        code_expired = self.client.post(
            "/api/v1/activate",
            json={**self.device_proof("activate", machine=machine_d), "code": fresh},
        )
        self.assertEqual(code_expired.status_code, 400)
        self.assertEqual(code_expired.json["code"], "EXPIRED")

    def test_rotation_rate_limit_reports_activation_limit(self):
        """换钥每日 3 次封顶，超限 code=ACTIVATION_LIMIT。"""
        machine = "E" * 64
        headers = {"X-Admin-Token": "test-admin"}
        self.client.post(
            "/api/v1/licenses/renew",
            headers=headers,
            json={"app_name": "ControlCommand", "machine_code": machine,
                  "expires_at": "2030-01-01"},
        )
        license_key = self.client.get(
            "/api/v1/licenses/active_key",
            query_string={"app_name": "ControlCommand", "machine_code": machine},
            headers=headers,
        ).json["data"]["license_key"]
        for index in range(3):
            rotate = self.device_proof(
                "register", machine=machine, key=Ed25519PrivateKey.generate()
            )
            rotate["license_key"] = license_key
            self.assertEqual(
                self.client.post("/api/v1/devices/register", json=rotate).status_code,
                200,
                f"rotation #{index + 1} should pass",
            )
        rotate = self.device_proof(
            "register", machine=machine, key=Ed25519PrivateKey.generate()
        )
        rotate["license_key"] = license_key
        blocked = self.client.post("/api/v1/devices/register", json=rotate)
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(blocked.json["code"], "ACTIVATION_LIMIT")


    def _paid_license(self, machine, expires_at="2030-01-01"):
        response = self.client.post(
            "/api/v1/licenses/renew",
            headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "expires_at": expires_at},
        )
        self.assertEqual(response.status_code, 200, response.json)
        return response.json["data"]["license_key"]

    def test_self_unbind_with_device_signature(self):
        """自助解绑：license_key + 本机签名双因子，停用本机授权（§8.8 自助模式）。"""
        machine = "77" * 32
        trial = self.apply_trial(machine=machine)
        license_key = trial.json["data"]["license_key"]

        # 无授权凭据且无管理员令牌 → 401
        self.assertEqual(
            self.client.post(
                "/api/v1/unbind", json={"app_name": "ControlCommand", "machine_code": machine}
            ).status_code,
            401,
        )

        # 他机 Token → MACHINE_MISMATCH
        foreign_key = self.apply_trial(machine="88" * 32).json["data"]["license_key"]
        mismatch = self.client.post(
            "/api/v1/unbind",
            json={**self.device_proof("unbind", machine=machine), "license_key": foreign_key},
        )
        self.assertEqual(mismatch.status_code, 403)
        self.assertEqual(mismatch.json["code"], "MACHINE_MISMATCH")

        # 自助解绑成功
        first = self.client.post(
            "/api/v1/unbind",
            json={**self.device_proof("unbind", machine=machine), "license_key": license_key},
        )
        self.assertEqual(first.status_code, 200, first.json)
        self.assertEqual(first.json["data"]["revoked_issues"], 1)
        self.assertTrue(first.json["data"]["credential_revoked"])

        latest = self.client.post(
            "/api/v1/licenses/latest", json=self.device_proof("latest", machine=machine)
        )
        self.assertEqual(latest.status_code, 403)
        self.assertEqual(latest.json["code"], "REVOKED")

    def test_transfer_moves_license_to_new_machine(self):
        """自助换机主路径：旧机授权迁移到新机，继承有效期，旧机吊销。"""
        old = "A1" * 32
        new = "B2" * 32
        license_key = self._paid_license(old)
        moved = self.client.post(
            "/api/v1/licenses/transfer",
            json={**self.device_proof("transfer", machine=new), "license_key": license_key},
        )
        self.assertEqual(moved.status_code, 200, moved.json)
        data = moved.json["data"]
        self.assertEqual(data["expires_at"], "2030-01-01")
        self.assertEqual(data["license_type"], "paid")
        self.assertEqual(data["channel"], "transfer")
        self.assertEqual(data["transfer_count"], 1)
        self.assertEqual(data["transfer_remaining"], 2)

        latest = self.client.post(
            "/api/v1/licenses/latest", json=self.device_proof("latest", machine=new)
        )
        self.assertEqual(latest.status_code, 200, latest.json)
        self.assertEqual(latest.json["data"]["license_key"], data["license_key"])

        self.assertEqual(
            self.client.post(
                "/api/v1/licenses/latest", json=self.device_proof("latest", machine=old)
            ).status_code,
            403,
        )

        with closing(sqlite3.connect(self.db)) as conn:
            row = conn.execute(
                "SELECT previous_issue_id, transfer_count, status FROM license_issues WHERE channel='transfer'"
            ).fetchone()
        self.assertEqual(row[1], 1)
        self.assertEqual(row[2], "active")
        with closing(sqlite3.connect(self.db)) as conn:
            linked = conn.execute(
                "SELECT status FROM license_issues WHERE issue_id=?", (row[0],)
            ).fetchone()
        self.assertEqual(linked[0], "revoked")

    def test_transfer_limit_blocks_lineage(self):
        """换机按谱系计次：默认 3 次内可迁移，超限 ACTIVATION_LIMIT。"""
        current_machine = "C3" * 32
        current_key = self._paid_license(current_machine)
        for index in range(3):
            next_machine = str(index) * 64
            moved = self.client.post(
                "/api/v1/licenses/transfer",
                json={**self.device_proof("transfer", machine=next_machine),
                      "license_key": current_key},
            )
            self.assertEqual(moved.status_code, 200, moved.json)
            self.assertEqual(moved.json["data"]["transfer_count"], index + 1)
            current_key = moved.json["data"]["license_key"]
        blocked = self.client.post(
            "/api/v1/licenses/transfer",
            json={**self.device_proof("transfer", machine="9" * 64), "license_key": current_key},
        )
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(blocked.json["code"], "ACTIVATION_LIMIT")

    def test_transfer_rejects_same_machine_expired_revoked_and_forged(self):
        machine = "D4" * 32
        license_key = self._paid_license(machine)
        same = self.client.post(
            "/api/v1/licenses/transfer",
            json={**self.device_proof("transfer", machine=machine), "license_key": license_key},
        )
        self.assertEqual(same.status_code, 409)
        self.assertEqual(same.json["code"], "CONFLICT")

        expired_key = self._paid_license("E5" * 32, expires_at="2020-01-01")
        expired = self.client.post(
            "/api/v1/licenses/transfer",
            json={**self.device_proof("transfer", machine="F6" * 32), "license_key": expired_key},
        )
        self.assertEqual(expired.status_code, 403)
        self.assertEqual(expired.json["code"], "EXPIRED")

        revoked_machine = "A7" * 32
        revoked_key = self._paid_license(revoked_machine)
        self.client.post(
            "/api/v1/unbind",
            headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": revoked_machine},
        )
        revoked = self.client.post(
            "/api/v1/licenses/transfer",
            json={**self.device_proof("transfer", machine="B8" * 32), "license_key": revoked_key},
        )
        self.assertEqual(revoked.status_code, 403)
        self.assertEqual(revoked.json["code"], "REVOKED")

        proof = self.device_proof("transfer", machine="C9" * 32)
        proof["signature"] = "A" * 86
        forged = self.client.post(
            "/api/v1/licenses/transfer",
            json={**proof, "license_key": self._paid_license("D0" * 32)},
        )
        self.assertEqual(forged.status_code, 403)
        self.assertEqual(forged.json["code"], "SIGNATURE_INVALID")

    def test_transfer_preserves_trial_type_and_revokes_old_credential(self):
        old = "F1" * 32
        trial = self.apply_trial(machine=old)
        new = "A2" * 32
        moved = self.client.post(
            "/api/v1/licenses/transfer",
            json={**self.device_proof("transfer", machine=new),
                  "license_key": trial.json["data"]["license_key"]},
        )
        self.assertEqual(moved.status_code, 200, moved.json)
        self.assertEqual(moved.json["data"]["license_type"], "trial")
        self.assertEqual(moved.json["data"]["expires_at"], trial.json["data"]["expires_at"])
        old_latest = self.client.post(
            "/api/v1/licenses/latest", json=self.device_proof("latest", machine=old)
        )
        self.assertEqual(old_latest.status_code, 403)
        self.assertEqual(old_latest.json["code"], "REVOKED")


    def test_recovery_code_same_machine_restores_token(self):
        """同机恢复：私钥+Token 双丢后凭恢复码换绑公钥，原 Token 原样返还。"""
        machine = "33" * 32
        trial = self.apply_trial(machine=machine)
        created = self.client.post(
            "/api/v1/licenses/recovery-codes",
            headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "count": 2},
        )
        self.assertEqual(created.status_code, 200, created.json)
        codes = created.json["data"]["codes"]
        self.assertEqual(created.json["data"]["issue_id"], trial.json["data"]["issue_id"])
        self.assertEqual(len(codes), 2)

        # 换新钥（模拟私钥丢失）恢复：同机 → 换绑公钥 + 原 Token 返还
        new_key = Ed25519PrivateKey.generate()
        recovered = self.client.post(
            "/api/v1/licenses/recover",
            json={
                **self.device_proof("recover", machine=machine, key=new_key),
                "code": codes[0],
            },
        )
        self.assertEqual(recovered.status_code, 200, recovered.json)
        self.assertEqual(recovered.json["data"]["issue_id"], trial.json["data"]["issue_id"])
        self.assertEqual(recovered.json["data"]["license_key"], trial.json["data"]["license_key"])
        self.assertEqual(recovered.json["data"]["channel"], "recovery_same")

        latest = self.client.post(
            "/api/v1/licenses/latest", json=self.device_proof("latest", machine=machine, key=new_key)
        )
        self.assertEqual(latest.status_code, 200, latest.json)

        # 一码一次性
        again = self.client.post(
            "/api/v1/licenses/recover",
            json={**self.device_proof("recover", machine=machine, key=new_key), "code": codes[0]},
        )
        self.assertEqual(again.status_code, 400)
        self.assertEqual(again.json["code"], "CONFLICT")

    def test_recovery_code_cross_machine_behaves_like_transfer(self):
        """异机恢复：旧机解绑、新机签发，继承有效期，不占 transfer_count。"""
        old = "44" * 32
        trial = self.apply_trial(machine=old)
        codes = self.client.post(
            "/api/v1/licenses/recovery-codes",
            headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": old, "count": 1},
        ).json["data"]["codes"]

        new = "55" * 32
        moved = self.client.post(
            "/api/v1/licenses/recover",
            json={**self.device_proof("recover", machine=new), "code": codes[0]},
        )
        self.assertEqual(moved.status_code, 200, moved.json)
        data = moved.json["data"]
        self.assertEqual(data["channel"], "recovery")
        self.assertEqual(data["transfer_count"], 0)
        self.assertEqual(data["expires_at"], trial.json["data"]["expires_at"])

        self.assertEqual(
            self.client.post(
                "/api/v1/licenses/latest", json=self.device_proof("latest", machine=old)
            ).status_code,
            403,
        )
        latest = self.client.post(
            "/api/v1/licenses/latest", json=self.device_proof("latest", machine=new)
        )
        self.assertEqual(latest.status_code, 200, latest.json)

    def test_recovery_code_rejects_bad_input(self):
        # 无有效授权 → NOT_FOUND
        missing = self.client.post(
            "/api/v1/licenses/recovery-codes",
            headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": "66" * 32},
        )
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json["code"], "NOT_FOUND")

        machine = "77" * 32
        self.apply_trial(machine=machine)
        codes = self.client.post(
            "/api/v1/licenses/recovery-codes",
            headers={"X-Admin-Token": "test-admin"},
            json={"app_name": "ControlCommand", "machine_code": machine, "count": 1},
        ).json["data"]["codes"]

        # 格式非法
        bad = self.client.post(
            "/api/v1/licenses/recover",
            json={**self.device_proof("recover", machine=machine), "code": "not-a-code"},
        )
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.json["code"], "INVALID_INPUT")

        # 码过期
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE recovery_codes SET expires_at='2020-01-01' WHERE status='issued'"
                )
        expired = self.client.post(
            "/api/v1/licenses/recover",
            json={**self.device_proof("recover", machine=machine), "code": codes[0]},
        )
        self.assertEqual(expired.status_code, 400)
        self.assertEqual(expired.json["code"], "EXPIRED")


if __name__ == "__main__":
    unittest.main()
