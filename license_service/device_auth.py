import base64
import binascii
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import hash_machine_code, normalize_machine_code
from .db import connect_db


CHALLENGE_TTL_SECONDS = 120
REGISTER_TTL_SECONDS = 900
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_ACTIONS = frozenset(("trial", "latest", "register"))


def check_machine_code(machine_code):
    if not isinstance(machine_code, str):
        raise ValueError("invalid machine_code")
    code = normalize_machine_code(machine_code)
    if len(code) < 8 or len(code) > 128 or not re.fullmatch(r"[A-Z0-9:_-]+", code):
        raise ValueError("invalid machine_code")
    return code


def decode_public_key(encoded):
    if not isinstance(encoded, str) or len(encoded) != 43 or not _BASE64URL.fullmatch(encoded):
        raise ValueError("invalid device_public_key")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=")
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid device_public_key") from exc
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
        raise ValueError("invalid device_public_key")
    return raw


def _signed_message(action, app_name, machine_code, challenge):
    return (
        f"license-service/device/v1\n{action}\n{app_name}\n{machine_code}\n{challenge}"
    ).encode("utf-8")


def create_challenge(app, *, app_name, machine_code, action):
    if not isinstance(action, str) or action not in _ACTIONS:
        raise ValueError("invalid action")
    code = check_machine_code(machine_code)
    machine_hash = hash_machine_code(code, app.config["MACHINE_CODE_SALT"])
    challenge = secrets.token_urlsafe(32)
    ttl = REGISTER_TTL_SECONDS if action == "register" else CHALLENGE_TTL_SECONDS
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        with conn:
            now = int(time.time())
            conn.execute("DELETE FROM device_challenges WHERE expires_at<=?", (now,))
            conn.execute(
                """INSERT INTO device_challenges(challenge, app_name, machine_code_hash, action, expires_at)
                   VALUES(?,?,?,?,?)""",
                (challenge, app_name, machine_hash, action, now + ttl),
            )
    finally:
        conn.close()
    return {"challenge": challenge, "expires_in": ttl}


def verify_proof(conn, *, app_name, machine_code, machine_hash, action, challenge, signature, public_key):
    if (
        not isinstance(challenge, str) or len(challenge) != 43
        or not _BASE64URL.fullmatch(challenge)
        or not isinstance(signature, str) or len(signature) != 86
        or not _BASE64URL.fullmatch(signature)
    ):
        raise ValueError("invalid device proof")
    row = conn.execute(
        """SELECT expires_at FROM device_challenges
           WHERE challenge=? AND app_name=? AND machine_code_hash=? AND action=?""",
        (challenge, app_name, machine_hash, action),
    ).fetchone()
    if not row or row["expires_at"] <= int(time.time()):
        raise PermissionError("invalid or expired challenge")
    try:
        raw_signature = base64.urlsafe_b64decode(signature + "==")
        if len(raw_signature) != 64 or base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode("ascii") != signature:
            raise ValueError("invalid device proof")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            raw_signature, _signed_message(action, app_name, machine_code, challenge)
        )
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise PermissionError("invalid device proof") from exc
    deleted = conn.execute(
        "DELETE FROM device_challenges WHERE challenge=? AND expires_at>?",
        (challenge, int(time.time())),
    )
    if deleted.rowcount != 1:
        raise PermissionError("invalid or expired challenge")


def device_key(conn, app_name, machine_hash):
    return conn.execute(
        """SELECT public_key, revoked FROM device_credentials
           WHERE app_name=? AND machine_code_hash=?""",
        (app_name, machine_hash),
    ).fetchone()
