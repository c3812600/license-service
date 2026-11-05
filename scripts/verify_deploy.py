#!/usr/bin/env python3
"""部署核对脚本：对照接口清单自动核对现网/测试环境的可用状态。

用法：
    python scripts/verify_deploy.py https://licenses.lonk.vip
    python scripts/verify_deploy.py http://127.0.0.1:8765 --admin-token <令牌>

逐项探测每个端点的「存在性 + 错误信封」，输出 PASS/FAIL 与三态汇总
（已部署 / 未部署 / 行为不符）。退出码 0 表示全部通过，1 表示有 FAIL。
只发无副作用的探测请求（空参数/缺鉴权），不会签发或修改任何授权。
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

TIMEOUT = 15


def call(method, url, body=None, token=None, timeout=TIMEOUT):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Admin-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"ok": False, "error": raw[:200], "code": ""}
    except Exception as exc:  # 网络层故障
        return 0, {"ok": False, "error": str(exc), "code": ""}


class Checker:
    def __init__(self, base, admin_token=None):
        self.base = base.rstrip("/")
        self.admin_token = admin_token
        self.rows = []

    def record(self, name, ok, detail):
        self.rows.append((name, ok, detail))
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name}: {detail}")

    def probe(self, name, method, path, body=None, token=None,
              want_status=None, want_code=None, want_ok=None):
        status, payload = call(method, self.base + path, body=body, token=token)
        problems = []
        if want_status is not None and status != want_status:
            problems.append(f"status={status} want {want_status}")
        if want_ok is not None and payload.get("ok") is not want_ok:
            problems.append(f"ok={payload.get('ok')} want {want_ok}")
        if want_code is not None and payload.get("code") != want_code:
            problems.append(f"code={payload.get('code')!r} want {want_code!r}")
        detail = f"status={status} code={payload.get('code')!r}"
        if payload.get("error"):
            detail += f" error={payload['error'][:60]!r}"
        self.record(name, not problems, "; ".join(problems) if problems else detail)

    def run(self):
        print(f"== 核对 {self.base} ==\n")

        # 1. 基础可达性
        status, health = call("GET", self.base + "/api/v1/health")
        data = health.get("data") or {}
        health_ok = (
            status == 200 and health.get("ok") is True
            and isinstance(data.get("allowed_apps"), list)
            and "trial_days" in data
        )
        detail = f"status={status} schema_version={data.get('schema_version')} " \
                 f"apps={len(data.get('allowed_apps') or [])} trial_days={data.get('trial_days')}"
        self.record("GET /health", health_ok, detail)

        status, pubkey = call("GET", self.base + "/api/v1/public-key")
        pem = (pubkey.get("data") or {}).get("public_key_pem") or ""
        self.record(
            "GET /public-key",
            status == 200 and "BEGIN PUBLIC KEY" in pem,
            f"status={status} pem={len(pem)}B",
        )

        # 2. 公开端点（空参数 → 预期 4xx + 业务码；404 表示未部署）
        public_probes = [
            ("POST /devices/challenge", "POST", "/api/v1/devices/challenge", {}, "INVALID_INPUT"),
            ("POST /trial/apply", "POST", "/api/v1/trial/apply", {}, "INVALID_INPUT"),
            ("POST /licenses/latest", "POST", "/api/v1/licenses/latest", {}, "INVALID_INPUT"),
            ("POST /activate", "POST", "/api/v1/activate", {}, "INVALID_INPUT"),
            ("POST /validate", "POST", "/api/v1/validate", {}, "INVALID_INPUT"),
            ("POST /licenses/transfer", "POST", "/api/v1/licenses/transfer", {}, "INVALID_INPUT"),
            ("POST /licenses/recover", "POST", "/api/v1/licenses/recover", {}, "INVALID_INPUT"),
        ]
        for name, method, path, body, code in public_probes:
            self.probe(name, method, path, body=body, want_ok=False, want_code=code)

        # 3. 旧接口必须保持 405
        self.probe(
            "GET /licenses/latest (legacy)", "GET", "/api/v1/licenses/latest",
            want_status=405, want_ok=False, want_code="METHOD_NOT_ALLOWED",
        )

        # 4. 管理端点：缺令牌 → 401 UNAUTHORIZED
        admin_probes = [
            ("POST /devices/revoke", "POST", "/api/v1/devices/revoke", {}),
            ("POST /devices/forget", "POST", "/api/v1/devices/forget", {}),
            ("POST /activation-codes", "POST", "/api/v1/activation-codes", {}),
            ("POST /licenses/recovery-codes", "POST", "/api/v1/licenses/recovery-codes", {}),
            ("GET /licenses/query", "GET", "/api/v1/licenses/query", None),
            ("GET /stats", "GET", "/api/v1/stats", None),
        ]
        for name, method, path, body in admin_probes:
            self.probe(name, method, path, body=body, want_status=401, want_ok=False,
                       want_code="UNAUTHORIZED")

        # 5. 自助路径缺凭据 → 401
        self.probe(
            "POST /unbind (no creds)", "POST", "/api/v1/unbind",
            body={"app_name": "x", "machine_code": "y"},
            want_status=401, want_ok=False, want_code="UNAUTHORIZED",
        )

        # 6. 带管理令牌（可选）
        if self.admin_token:
            self.probe("GET /stats (admin)", "GET", "/api/v1/stats",
                       token=self.admin_token, want_status=200, want_ok=True)
            self.probe("GET /devices (admin)", "GET", "/api/v1/devices",
                       token=self.admin_token, want_status=200, want_ok=True)
        else:
            print("[SKIP] 管理令牌核对（传 --admin-token 启用）")

        # 汇总
        total = len(self.rows)
        passed = sum(1 for _, ok, _ in self.rows if ok)
        print(f"\n== 汇总：{passed}/{total} 通过 ==")
        if passed != total:
            print("未通过项：")
            for name, ok, detail in self.rows:
                if not ok:
                    print(f"  - {name}: {detail}")
        return 0 if passed == total else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="license-service 部署核对")
    parser.add_argument("base_url", help="服务地址，如 https://licenses.lonk.vip")
    parser.add_argument("--admin-token", default=None, help="管理员令牌（可选，用于管理端核对）")
    args = parser.parse_args(argv)
    return Checker(args.base_url, args.admin_token).run()


if __name__ == "__main__":
    sys.exit(main())
