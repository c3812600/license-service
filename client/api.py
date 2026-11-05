"""license-service HTTP 客户端（stdlib urllib，无第三方依赖）。

每个方法对应规范 §8 的一个端点；返回服务端 `data` 字典，
失败抛 ApiError（携带 code 与 status，与错误信封一致）。
"""

import json
import urllib.error
import urllib.request


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(f"[{code or status}] {message}")
        self.status = status
        self.code = code
        self.message = message


class LicenseAPI:
    def __init__(self, base_url, timeout=15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _call(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            self.base_url + path, data=data,
            headers={"Content-Type": "application/json", **(headers or {})},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {"ok": False, "error": raw[:200], "code": ""}
            raise ApiError(exc.code, payload.get("code") or "", payload.get("error") or raw[:200]) from None
        except urllib.error.URLError as exc:
            raise ApiError(0, "SERVICE_UNAVAILABLE", str(exc.reason)) from None
        if not payload.get("ok"):
            raise ApiError(200, payload.get("code") or "", payload.get("error") or "unknown error")
        return payload.get("data") or {}

    # ---- 只读 ----

    def health(self):
        return self._call("GET", "/api/v1/health")

    def public_key_pem(self):
        return self._call("GET", "/api/v1/public-key")["public_key_pem"]

    # ---- 设备协议 ----

    def challenge(self, app_name, machine_code, action):
        return self._call("POST", "/api/v1/devices/challenge", {
            "app_name": app_name, "machine_code": machine_code, "action": action,
        })

    def apply_trial(self, **fields):
        return self._call("POST", "/api/v1/trial/apply", fields)

    def fetch_latest(self, **fields):
        return self._call("POST", "/api/v1/licenses/latest", fields)

    def activate(self, **fields):
        return self._call("POST", "/api/v1/activate", fields)

    def validate(self, **fields):
        return self._call("POST", "/api/v1/validate", fields)

    def transfer(self, **fields):
        return self._call("POST", "/api/v1/licenses/transfer", fields)

    def recover(self, **fields):
        return self._call("POST", "/api/v1/licenses/recover", fields)

    def register(self, **fields):
        return self._call("POST", "/api/v1/devices/register", fields)

    def unbind(self, **fields):
        return self._call("POST", "/api/v1/unbind", fields)
