import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import ForbiddenError, InputError


# App-specific prefixes
TOKEN_PREFIXES = {
    "ControlCommand": "RCC1",
    "E-Player": "EPL",
    "WinPilot": "WPL",
    "iCMS": "ICMS",
    "rust-node": "RUSTNODE",
}

# Default prefix for backward compatibility
TOKEN_PREFIX = "RCC1"


def _b64url_encode(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_machine_code(machine_code, salt):
    normalized = normalize_machine_code(machine_code)
    return _sha256(salt + "|" + normalized)


def hash_license_token(token):
    return _sha256(token)


def normalize_machine_code(machine_code):
    return str(machine_code or "").strip().upper()


def ensure_keypair(private_key_path, public_key_path, *, allow_generate=True):
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)

    if private_path.exists() != public_path.exists():
        raise RuntimeError("incomplete signing keypair; restore the missing key from backup")
    if private_path.exists():
        private_key = _load_private_key(private_path)
        public_key = serialization.load_pem_public_key(public_path.read_bytes())
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise RuntimeError("signing keys must be Ed25519")
        private_public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        stored_public = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if private_public != stored_public:
            raise RuntimeError("signing private and public keys do not match")
        return

    if not allow_generate:
        raise RuntimeError("signing keypair is missing; restore it from backup")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Exclusive creation prevents a second process from silently replacing the trust anchor.
    with private_path.open("xb") as output:
        output.write(private_bytes)
    if os.name != "nt":
        private_path.chmod(0o600)
    with public_path.open("xb") as output:
        output.write(public_bytes)


def _load_private_key(private_key_path):
    private_bytes = Path(private_key_path).read_bytes()
    return serialization.load_pem_private_key(private_bytes, password=None)


def sign_license_payload(payload, private_key_path, app_name=None):
    """Sign license payload with app-specific prefix."""
    private_key = _load_private_key(private_key_path)
    payload_bytes = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = private_key.sign(payload_bytes)
    
    # Use app-specific prefix if provided
    prefix = TOKEN_PREFIXES.get(app_name, TOKEN_PREFIX) if app_name else TOKEN_PREFIX
    
    return "{prefix}.{payload}.{signature}".format(
        prefix=prefix,
        payload=_b64url_encode(payload_bytes),
        signature=_b64url_encode(signature),
    )


def _b64url_decode(text):
    raw = str(text).encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def verify_license_payload(license_key, public_key_path, app_name=None):
    """校验服务端自签授权码并返回 payload 字典。

    核验前缀与 Ed25519 签名（覆盖 payload 原始字节，与签发逐字节同构）；
    调用方再做 app/机器码/到期日绑定核对。失败抛 ValueError/PermissionError。
    """
    parts = str(license_key or "").strip().split(".")
    if len(parts) != 3:
        raise InputError("invalid license_key format")
    prefix, payload_b64, signature_b64 = parts
    expected = TOKEN_PREFIXES.get(app_name, TOKEN_PREFIX) if app_name else TOKEN_PREFIX
    if prefix != expected:
        raise InputError("license_key prefix mismatch", "PRODUCT_MISMATCH")
    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(signature_b64)
    except Exception as exc:
        raise InputError("invalid license_key encoding") from exc
    loaded = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    der = loaded.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        Ed25519PublicKey.from_public_bytes(der[-32:]).verify(signature, payload_bytes)
    except Exception as exc:
        raise ForbiddenError("license_key signature invalid", "SIGNATURE_INVALID") from exc
    return json.loads(payload_bytes.decode("utf-8"))
