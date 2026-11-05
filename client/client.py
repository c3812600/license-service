"""高层客户端门面：一条链路走完「采集机器码 → 领试用/激活 → 取授权 → 离线验签」。

使用示例：

    from client import LicenseClient

    client = LicenseClient("https://licenses.lonk.vip", app_name="ControlCommand")
    result = client.ensure_trial()          # 首次申请试用；已登记则直接领
    payload = client.verify(result["license_key"])   # 离线验签（防伪）
    state = client.validate(result["license_key"])   # 在线状态核查（可选）

机器码采集/密钥持久化/防回拨状态按规范附录 A、C、K 实现，详见各模块。
"""

from .api import ApiError, LicenseAPI
from .keys import load_or_create_keypair
from .machine_code import collect_machine_code
from .protocol import (
    normalize_machine_code,
    raw_public_key_b64url,
    sign_proof,
    verify_license_token,
)
from .state import LocalCache, LocalState


class LicenseClient:
    def __init__(self, base_url, app_name, key_dir=None, api=None, trial_days=30):
        self.api = api or LicenseAPI(base_url)
        self.app_name = app_name
        self.trial_days = trial_days
        self.key_dir = key_dir
        self.cache = LocalCache(key_dir)
        self.machine_code, self.machine_path, self.machine_source = collect_machine_code(self.cache)
        self.private_key, self.public_key = load_or_create_keypair(key_dir)
        self.state = LocalState(key_dir, self.private_key)

    # ---- 内部：设备证明 ----

    def _proof(self, action):
        machine = normalize_machine_code(self.machine_code)
        challenge = self.api.challenge(self.app_name, machine, action)["challenge"]
        return {
            "app_name": self.app_name,
            "machine_code": machine,
            "challenge": challenge,
            "signature": sign_proof(action, self.app_name, machine, challenge, self.private_key),
            "device_public_key": raw_public_key_b64url(self.public_key),
        }

    def _record(self, issued):
        if self.state.check_no_rollback(
            self.state.verify(self.public_key),
            issued.get("expires_at", ""), issued.get("issue_id", ""), self.public_key,
        ):
            self.state.save(
                expires_at=issued.get("expires_at", ""),
                issue_id=issued.get("issue_id", ""),
                server_time=issued.get("issued_at", ""),
            )
        return issued

    # ---- 主流程 ----

    def ensure_trial(self):
        """自助试用：未登记首申；已登记重复领取（沿用首次到期日）。"""
        issued = self.api.apply_trial(
            **self._proof("trial"),
            trial_days=self.trial_days,
        )
        return self._record(issued)

    def fetch_latest(self):
        """领取本机未过期的在线授权；无有效授权抛 ApiError(code=LICENSE_REQUIRED)。"""
        issued = self.api.fetch_latest(**self._proof("latest"))
        return self._record(issued)

    def activate(self, code, app_version=""):
        """一次性激活码兑换：核销 + 绑定 + 签发同一事务。"""
        issued = self.api.activate(
            **self._proof("activate"), code=code, app_version=app_version,
        )
        return self._record(issued)

    def transfer(self, license_key, app_version=""):
        """自助换机：把 license_key 对应授权迁移到本机（本机即新机）。"""
        issued = self.api.transfer(
            **self._proof("transfer"), license_key=license_key, app_version=app_version,
        )
        return self._record(issued)

    def recover(self, code, app_version=""):
        """凭恢复码重新绑定本机（私钥+Token 双丢后的救命稻草）。"""
        issued = self.api.recover(
            **self._proof("recover"), code=code, app_version=app_version,
        )
        return self._record(issued)

    def unbind_self(self, license_key):
        """自助解绑：停用本机授权（双因子：license_key + 本机签名）。"""
        return self.api.unbind(
            app_name=self.app_name,
            machine_code=normalize_machine_code(self.machine_code),
            license_key=license_key,
            **{k: v for k, v in self._proof("unbind").items() if k in ("challenge", "signature")},
        )

    def validate(self, license_token):
        """在线状态核查：返回 {status, server_time, ...}，不签发新 Token。"""
        return self.api.validate(
            **self._proof("validate"), license_token=license_token,
        )

    def verify(self, license_token):
        """离线验签 + 绑定核对；返回 payload。任何不符抛 ValueError/PermissionError。"""
        payload = verify_license_token(
            license_token, self.api.public_key_pem(), app_name=self.app_name,
        )
        if payload.get("app_name") != self.app_name:
            raise PermissionError("license app mismatch")
        if normalize_machine_code(payload.get("machine_code")) != normalize_machine_code(self.machine_code):
            raise PermissionError("license machine mismatch")
        return payload
