"""license-service 参考客户端（规范 §八 / 附录 A–D、K 的可运行实现）。

模块：
    protocol    设备证明签名、Token 离线验签（跨语言向量见 tests/test_reference_client.py）
    machine_code 机器码采集（Windows 强路径 / Linux DMI，附录 A、K）
    keys        设备 Ed25519 密钥对持久化（DPAPI / 0600）
    state       机器码缓存 + 防回拨状态（附录 C）
    api         HTTP 客户端（错误码透传）
    client      LicenseClient 高层门面
"""

from .api import ApiError, LicenseAPI
from .client import LicenseClient
from .keys import generate_keypair, load_or_create_keypair, load_private_key
from .machine_code import collect_machine_code, normalize_hw, probe_machine_code
from .protocol import (
    TOKEN_PREFIXES,
    normalize_machine_code,
    raw_public_key_b64url,
    sign_proof,
    signed_message,
    verify_license_token,
)
from .state import LocalCache, LocalState

__all__ = [
    "ApiError", "LicenseAPI", "LicenseClient",
    "generate_keypair", "load_or_create_keypair", "load_private_key", "raw_public_key_b64url",
    "collect_machine_code", "normalize_hw", "probe_machine_code",
    "TOKEN_PREFIXES", "normalize_machine_code", "sign_proof", "signed_message",
    "verify_license_token", "LocalCache", "LocalState",
]
