import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def _resolve_path(raw_value, default_relative_path):
    value = (raw_value or "").strip()
    if not value:
        value = default_relative_path
    path = Path(value)
    if not path.is_absolute():
        path = BASE_DIR / path
    return str(path.resolve())


class Config:
    SECRET_KEY = os.environ.get("LICENSE_SERVICE_SECRET_KEY") or "change-me"
    ADMIN_TOKEN = os.environ.get("LICENSE_SERVICE_ADMIN_TOKEN") or ""
    MACHINE_CODE_SALT = os.environ.get("LICENSE_SERVICE_MACHINE_CODE_SALT") or "change-me"
    TRIAL_DAYS = int(os.environ.get("LICENSE_SERVICE_TRIAL_DAYS") or "365")
    ALLOWED_APP_NAMES = tuple(
        item.strip()
        for item in (os.environ.get("LICENSE_SERVICE_ALLOWED_APPS") or "ControlCommand,E-Player,WinPilot").split(",")
        if item.strip()
    )
    DATABASE_PATH = _resolve_path(
        os.environ.get("LICENSE_SERVICE_DB_PATH"),
        "data/license-service.db",
    )
    PRIVATE_KEY_PATH = _resolve_path(
        os.environ.get("LICENSE_PRIVATE_KEY_PATH"),
        "keys/ed25519-private.pem",
    )
    PUBLIC_KEY_PATH = _resolve_path(
        os.environ.get("LICENSE_PUBLIC_KEY_PATH"),
        "keys/ed25519-public.pem",
    )
