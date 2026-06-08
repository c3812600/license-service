import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# App-specific prefixes
TOKEN_PREFIXES = {
    "ControlCommand": "RCC1",
    "E-Player": "EPL",
    "WinPilot": "WPL",
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


def ensure_keypair(private_key_path, public_key_path):
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)

    if private_path.exists() and public_path.exists():
        return

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

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)


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
