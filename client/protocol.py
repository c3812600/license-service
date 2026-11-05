"""设备协议原语：规范化签名消息、base64url、License Token 离线验签。

签名消息格式（与服务端 `license_service/device_auth.py::_signed_message` 逐字节一致，
跨语言向量见 `tests/test_reference_client.py`）：

    license-service/device/v1\n{action}\n{app_name}\n{normalized_machine_code}\n{challenge}

无尾部换行。Token 格式见规范附录 B：`<产品前缀>.<base64url(payload)>.<base64url(签名)>`，
签名覆盖 payload 的原始 JSON 字节。
"""

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TOKEN_PREFIXES = {
    "ControlCommand": "RCC1",
    "E-Player": "EPL",
    "WinPilot": "WPL",
    "iCMS": "ICMS",
    "rust-node": "RUSTNODE",
}
DEFAULT_PREFIX = "RCC1"


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    raw = str(text).encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def signed_message(action, app_name, machine_code, challenge):
    """设备证明的签名输入；machine_code 须先 normalize_machine_code。"""
    return (
        f"license-service/device/v1\n{action}\n{app_name}\n{machine_code}\n{challenge}"
    ).encode("utf-8")


def normalize_machine_code(machine_code):
    return str(machine_code or "").strip().upper()


def sign_proof(action, app_name, machine_code, challenge, private_key):
    """对挑战签名，返回 86 位无填充 base64url 签名。"""
    signature = private_key.sign(
        signed_message(action, app_name, normalize_machine_code(machine_code), challenge)
    )
    return b64url_encode(signature)


def raw_public_key_b64url(public_key):
    """32 字节原始公钥的 43 位无填充 base64url 编码。"""
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b64url_encode(raw)


def verify_license_token(license_key, public_key_pem, app_name=None):
    """离线校验服务端自签 Token：前缀 + Ed25519 签名 + payload 解析。

    返回 payload 字典；调用方再核对 app_name / machine_code / expires_at 绑定。
    失败抛 ValueError（格式）或 PermissionError（签名）。
    """
    parts = str(license_key or "").strip().split(".")
    if len(parts) != 3:
        raise ValueError("invalid license_key format")
    prefix, payload_b64, signature_b64 = parts
    expected = (TOKEN_PREFIXES.get(app_name, DEFAULT_PREFIX) if app_name else DEFAULT_PREFIX)
    if prefix != expected:
        raise ValueError("license_key prefix mismatch")
    try:
        payload_bytes = b64url_decode(payload_b64)
        signature = b64url_decode(signature_b64)
    except Exception as exc:
        raise ValueError("invalid license_key encoding") from exc
    loaded = serialization.load_pem_public_key(
        public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    )
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    try:
        loaded.verify(signature, payload_bytes)
    except InvalidSignature as exc:
        raise PermissionError("license_key signature invalid") from exc
    return json.loads(payload_bytes.decode("utf-8"))
