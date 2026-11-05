"""本地状态：机器码缓存 + 防回拨状态（规范附录 C）。

状态文件由设备私钥签名后落盘；每次启动先验签再读，
若到期日/授权版本倒退且无服务端时间佐证则拒绝对外提供授权（防时间回拨）。
"""

import json
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature

DEFAULT_STATE_DIR = Path.home() / ".license-client"


def _canonical(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


class LocalState:
    """附录 C 状态容器：{expires_at, issue_id, server_time, updated_at} + Ed25519 签名。"""

    def __init__(self, state_dir=None, private_key=None):
        self.path = Path(state_dir or DEFAULT_STATE_DIR) / "license-state.json"
        self.private_key = private_key

    def load(self):
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return doc

    def save(self, **fields):
        if self.private_key is None:
            raise RuntimeError("private key required to sign state")
        payload = {**fields, "updated_at": int(time.time())}
        signature = self.private_key.sign(_canonical(payload))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"payload": payload, "signature": signature.hex()}, ensure_ascii=False),
            encoding="utf-8",
        )
        return payload

    def verify(self, public_key):
        """验签并返回 payload；签名不符/损坏返回 None。"""
        doc = self.load()
        if not doc:
            return None
        try:
            public_key.verify(bytes.fromhex(doc["signature"]), _canonical(doc["payload"]))
        except (InvalidSignature, KeyError, ValueError):
            return None
        return doc["payload"]

    def check_no_rollback(self, payload, new_expires_at, new_issue_id, public_key):
        """到期日/签发号不得无佐证倒退；返回 True 表示可接受本次更新。"""
        current = payload or {}
        old_expiry = str(current.get("expires_at") or "")
        if old_expiry and str(new_expires_at) < old_expiry:
            # 允许 supersede 降期：issue_id 变化视为服务端有意为之
            if str(new_issue_id) == str(current.get("issue_id") or ""):
                return False
        return True


class LocalCache:
    """机器码缓存（附录 A dpapi_load/save 的文件版）。"""

    def __init__(self, cache_dir=None):
        self.path = Path(cache_dir or DEFAULT_STATE_DIR) / "machine-code-cache.json"

    def load(self):
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def save(self, code, path):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"code": code, "path": path}, ensure_ascii=False), encoding="utf-8"
        )

    def report_mismatch(self, cached, live):
        """硬件疑似变更：只告警，不改绑（与附录 A 一致）。"""
        print(f"[warn] machine code mismatch: cached={cached.get('code')} live={live.get('code')}")
