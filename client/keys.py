"""设备 Ed25519 密钥对的生成与持久化（规范 §三 / 附录 K）。

私钥仅留客户端：Windows 用 DPAPI 加密落盘，其余平台 0600 权限 PEM。
公钥以 32 字节原始形式、无填充 base64url（43 字符）上传。
"""

import os
import platform
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DEFAULT_KEY_DIR = Path.home() / ".license-client"


def _dpapi_protect(raw):
    import ctypes
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    in_buf = ctypes.create_string_buffer(raw)
    in_blob = DATA_BLOB(len(raw), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_blob), "license-client-key", None, None, None, 0, ctypes.byref(out_blob)
    ):
        raise OSError("DPAPI CryptProtectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(blob):
    import ctypes
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    in_buf = ctypes.create_string_buffer(blob, len(blob))
    in_blob = DATA_BLOB(len(blob), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    ):
        raise OSError("DPAPI CryptUnprotectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _write_private(path, data, protect):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _dpapi_protect(data) if protect else data
    with open(path, "wb") as output:
        output.write(payload)
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def generate_keypair(key_dir=None):
    """生成并持久化密钥对，返回 (private_key, public_key)。"""
    key_dir = Path(key_dir or DEFAULT_KEY_DIR)
    private_path = key_dir / "device-key.bin"
    if private_path.exists():
        raise FileExistsError(private_path)
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    _write_private(private_path, raw, protect=(platform.system() == "Windows"))
    return private_key, private_key.public_key()


def load_private_key(key_dir=None):
    key_dir = Path(key_dir or DEFAULT_KEY_DIR)
    raw = (key_dir / "device-key.bin").read_bytes()
    if platform.system() == "Windows":
        raw = _dpapi_unprotect(raw)
    if len(raw) != 32:
        raise ValueError("invalid device key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_or_create_keypair(key_dir=None):
    key_dir = Path(key_dir or DEFAULT_KEY_DIR)
    if (key_dir / "device-key.bin").exists():
        private_key = load_private_key(key_dir)
        return private_key, private_key.public_key()
    return generate_keypair(key_dir)
