"""参考客户端测试：协议向量、Token 验签、机器码格式、防回拨状态。

跨语言向量与服务端 test_device_signature_cross_language_vector 完全一致——
任何语言的客户端实现都应复现同一组字节。
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client import (
    LocalState,
    normalize_hw,
    sign_proof,
    signed_message,
    verify_license_token,
)
from client.keys import load_or_create_keypair
from client.protocol import TOKEN_PREFIXES, b64url_encode, raw_public_key_b64url
from license_service.crypto import sign_license_payload

# 与 tests/test_service.py::test_device_signature_cross_language_vector 相同的向量
VECTOR_SEED = bytes(range(32))
VECTOR_PUBLIC_KEY = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
VECTOR_SIGNATURE = (
    "HNhvGmg8ez2IrCEP2uypAGDkMHOmGsribExv25ujZSZ5zRIxKdfLucahMQRhufmCdjcWFRJxd1Ljvu2KKUIeAw"
)


class ProtocolVectorTests(unittest.TestCase):
    def test_cross_language_signature_vector(self):
        key = Ed25519PrivateKey.from_private_bytes(VECTOR_SEED)
        message = signed_message("latest", "ControlCommand", "A" * 64, "A" * 43)
        self.assertEqual(len(message), 156)
        self.assertEqual(raw_public_key_b64url(key.public_key()), VECTOR_PUBLIC_KEY)
        self.assertEqual(
            sign_proof("latest", "ControlCommand", "A" * 64, "A" * 43, key),
            VECTOR_SIGNATURE,
        )

    def test_machine_code_normalized_before_signing(self):
        key = Ed25519PrivateKey.from_private_bytes(VECTOR_SEED)
        self.assertEqual(
            sign_proof("latest", "ControlCommand", " \t" + "a" * 64 + " ", "A" * 43, key),
            VECTOR_SIGNATURE,
        )


class TokenVerifyTests(unittest.TestCase):
    def test_roundtrip_sign_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            private_path = Path(tmp) / "private.pem"
            public_path = Path(tmp) / "public.pem"
            key = Ed25519PrivateKey.generate()
            from cryptography.hazmat.primitives import serialization
            private_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            public_path.write_bytes(key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            token = sign_license_payload(
                {"ver": 1, "issue_id": "x", "app_name": "ControlCommand",
                 "machine_code": "A" * 64, "license_type": "trial",
                 "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01"},
                str(private_path), app_name="ControlCommand",
            )
            payload = verify_license_token(
                token, public_path.read_text(encoding="utf-8"), app_name="ControlCommand",
            )
            self.assertEqual(payload["issue_id"], "x")
            self.assertEqual(payload["machine_code"], "A" * 64)

    def test_prefix_and_signature_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            from license_service.crypto import ensure_keypair
            private_path = Path(tmp) / "private.pem"
            public_path = Path(tmp) / "public.pem"
            ensure_keypair(str(private_path), str(public_path))
            token = sign_license_payload(
                {"ver": 1, "app_name": "ControlCommand"}, str(private_path),
                app_name="ControlCommand",
            )
            pem = public_path.read_text(encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_license_token("not-a-token", pem, app_name="ControlCommand")
            with self.assertRaises(ValueError):
                verify_license_token(token, pem, app_name="E-Player")  # 前缀不符
            tampered = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
            with self.assertRaises(PermissionError):
                verify_license_token(tampered, pem, app_name="ControlCommand")

    def test_prefix_table_covers_registered_apps(self):
        self.assertEqual(TOKEN_PREFIXES["ControlCommand"], "RCC1")
        self.assertEqual(len(set(TOKEN_PREFIXES.values())), len(TOKEN_PREFIXES))


class MachineCodeFormatTests(unittest.TestCase):
    def test_normalize_hw_rejects_placeholder_values(self):
        self.assertEqual(normalize_hw("  to be filled by o.e.m.  "), "")
        self.assertEqual(normalize_hw(None), "")
        self.assertEqual(normalize_hw(" abc-123 "), "ABC-123")

    def test_probe_returns_code_and_path_shape(self):
        from client.machine_code import probe_machine_code
        code, path = probe_machine_code()
        if code is not None:
            self.assertRegex(code, r"^[0-9A-F]{8}$|^[0-9A-F]{64}$")
            self.assertIn(path, (1, 2, 3, 4))


class RollbackStateTests(unittest.TestCase):
    def test_state_signing_and_rollback_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_dir = Path(tmp)
            private_key, public_key = load_or_create_keypair(key_dir)
            state = LocalState(key_dir, private_key)
            state.save(expires_at="2030-01-01", issue_id="i1")
            payload = state.verify(public_key)
            self.assertEqual(payload["expires_at"], "2030-01-01")

            # 同 issue_id 到期日倒退 → 拒绝
            self.assertFalse(state.check_no_rollback(payload, "2029-01-01", "i1", public_key))
            # 新签发（supersede 降期）→ 接受
            self.assertTrue(state.check_no_rollback(payload, "2029-01-01", "i2", public_key))
            # 顺延 → 接受
            self.assertTrue(state.check_no_rollback(payload, "2031-01-01", "i3", public_key))

    def test_state_rejects_forged_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_dir = Path(tmp)
            private_key, public_key = load_or_create_keypair(key_dir)
            state = LocalState(key_dir, private_key)
            state.save(expires_at="2030-01-01", issue_id="i1")
            doc = json.loads(state.path.read_text(encoding="utf-8"))
            doc["payload"]["expires_at"] = "2099-12-31"
            state.path.write_text(json.dumps(doc), encoding="utf-8")
            self.assertIsNone(state.verify(public_key))


if __name__ == "__main__":
    unittest.main()
