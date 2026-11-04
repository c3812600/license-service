import hmac
import ipaddress
import logging
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .crypto import ensure_keypair
from .db import init_db
from .device_auth import create_challenge
from .service import (
    fetch_latest_license, issue_offline_license, issue_trial_license, license_stats, forget_machine, query_licenses, register_device, renew_license, revoke_device, validate_app_name, list_devices, update_device_meta, touch_device, fetch_active_license_key,
)


def _error(message, status_code=400):
    return jsonify({"ok": False, "error": message}), status_code


# 生产拓扑：cloudflared 容器（172.17.0.3）→ 10.0.0.228:8765，代理头只信任本机/容器网桥来源；
# 直连 8765 的客户端伪造 X-Forwarded-For 会被剥掉，审计 IP 不可伪造（体检 R2）。
_TRUSTED_PROXY_NETS = tuple(
    ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128", "172.16.0.0/12")
)


def _strip_untrusted_proxy_headers(environ):
    """非可信来源（局域网直连等）的代理头一律剥掉，按真实来源 IP 记审计/限流。"""
    remote = environ.get("REMOTE_ADDR") or ""
    try:
        addr = ipaddress.ip_address(remote)
    except ValueError:
        trusted = False
    else:
        trusted = any(addr in net for net in _TRUSTED_PROXY_NETS)
    if not trusted:
        for key in ("HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED_PROTO", "HTTP_X_FORWARDED_HOST"):
            environ.pop(key, None)
    return environ


def _ok(data=None):
    return jsonify({"ok": True, "data": data or {}})


def _require_admin_token(app):
    configured = app.config.get("ADMIN_TOKEN") or ""
    incoming = (request.headers.get("X-Admin-Token") or "").strip()
    if not configured:
        return _error("admin token is not configured", 500)
    if not hmac.compare_digest(incoming, configured):
        return _error("unauthorized", 401)
    return None


_RATE_LOCK = threading.Lock()
_RATE_HITS = {}
# 公开接口限流：路径 -> (次数, 窗口秒)。防御恶意刷挑战/试用（代理限流之外的兜底）。
_RATE_LIMITS = {
    "/api/v1/devices/challenge": (30, 60),
    "/api/v1/trial/apply": (5, 60),
    "/api/v1/licenses/latest": (10, 60),
}


def _rate_limited(ip, path, limit, window):
    now = time.time()
    key = (ip, path)
    with _RATE_LOCK:
        hits = [t for t in _RATE_HITS.get(key, []) if now - t < window]
        if len(hits) >= limit:
            _RATE_HITS[key] = hits
            return True
        hits.append(now)
        _RATE_HITS[key] = hits
    return False


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    # 真实客户端 IP（审计溯源）：只对可信代理来源采纳 XFF——见 _strip_untrusted_proxy_headers
    inner = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    def _trusted_proxy_only(environ, start_response):
        _strip_untrusted_proxy_headers(environ)
        return inner(environ, start_response)

    app.wsgi_app = _trusted_proxy_only

    static_dir = Path(__file__).resolve().parent / "static"

    @app.get("/admin")
    def admin_page():
        return send_from_directory(static_dir, "admin.html")

    @app.get("/admin/stats")
    def stats_page():
        return send_from_directory(static_dir, "stats.html")

    @app.get("/admin/<path:filename>")
    def admin_static(filename):
        return send_from_directory(static_dir, filename)

    ensure_keypair(
        app.config["PRIVATE_KEY_PATH"], app.config["PUBLIC_KEY_PATH"],
        allow_generate=not Path(app.config["DATABASE_PATH"]).exists(),
    )
    init_db(app.config["DATABASE_PATH"])

    @app.after_request
    def prevent_sensitive_caching(response):
        if request.path.startswith("/api/v1/") or request.path.startswith("/admin"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.before_request
    def _rate_limit():
        if not app.config.get("RATE_LIMIT_ENABLED", True):
            return None
        lim = _RATE_LIMITS.get(request.path)
        if lim and request.method == "POST":
            if _rate_limited(request.remote_addr or "", request.path, *lim):
                return _error("too many requests", 429)
        return None

    @app.errorhandler(Exception)
    def _unhandled(e):
        if isinstance(e, HTTPException):
            # 404/405 等也走 {"ok":false,"error":...} JSON 契约（体检 P2-3 残留）
            return _error(e.description or e.name, e.code or 500)
        logging.getLogger("license_service").exception("unhandled error")
        return _error("internal server error", 500)

    @app.get("/api/v1/health")
    def health():
        return _ok(
            {
                "service": "rcc-license-service",
                "allowed_apps": list(app.config["ALLOWED_APP_NAMES"]),
                "trial_days": app.config["TRIAL_DAYS"],
            }
        )

    @app.get("/api/v1/public-key")
    def public_key():
        public_key_text = Path(app.config["PUBLIC_KEY_PATH"]).read_text(encoding="utf-8")
        return _ok({"public_key_pem": public_key_text})

    @app.post("/api/v1/devices/challenge")
    def device_challenge():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _error("JSON object required")
        try:
            validate_app_name(app, data.get("app_name"))
            return _ok(create_challenge(
                app, app_name=data["app_name"],
                machine_code=data.get("machine_code"), action=data.get("action"),
            ))
        except ValueError as exc:
            return _error(str(exc))

    @app.post("/api/v1/trial/apply")
    def apply_trial():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _error("JSON object required")
        app_name = data.get("app_name")
        machine_code = data.get("machine_code")
        app_version = data.get("app_version") or ""
        if not isinstance(app_name, str) or not app_name.strip():
            return _error("app_name is required")
        if not isinstance(machine_code, str) or not machine_code.strip():
            return _error("machine_code is required")
        if not isinstance(app_version, str):
            return _error("invalid app_version")
        try:
            issued = issue_trial_license(
                app,
                app_name=app_name.strip(),
                machine_code=machine_code,
                device_public_key=data.get("device_public_key"),
                challenge=data.get("challenge"),
                signature=data.get("signature"),
                trial_days=data.get("trial_days"),
                app_version=app_version.strip(),
                client_ip=request.remote_addr or "",
                user_agent=request.headers.get("User-Agent") or "",
            )
            return _ok(issued)
        except ValueError as exc:
            return _error(str(exc), 400)
        except PermissionError as exc:
            return _error(str(exc), 403)
        except RuntimeError as exc:
            return _error(str(exc), 409)

    @app.post("/api/v1/licenses/renew")
    def renew():
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error

        data = request.get_json(silent=True) or {}
        app_name = (data.get("app_name") or "").strip()
        machine_code = (data.get("machine_code") or "").strip()
        expires_at = (data.get("expires_at") or "").strip()
        if not app_name:
            return _error("app_name is required")
        if not machine_code:
            return _error("machine_code is required")
        if not expires_at:
            return _error("expires_at is required")

        try:
            issued = renew_license(
                app,
                app_name=app_name,
                machine_code=machine_code,
                expires_at=expires_at,
                license_type=(data.get("license_type") or "paid").strip() or "paid",
                customer_name=(data.get("customer_name") or "").strip(),
                notes=(data.get("notes") or "").strip(),
                previous_issue_id=(data.get("previous_issue_id") or "").strip(),
                supersede=bool(data.get("supersede")),
                created_by="admin_api",
                client_ip=request.remote_addr or "",
                user_agent=request.headers.get("User-Agent") or "",
            )
            return _ok(issued)
        except ValueError as exc:
            return _error(str(exc), 400)

    @app.post("/api/v1/licenses/offline-issue")
    def offline_issue():
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error

        data = request.get_json(silent=True) or {}
        app_name = (data.get("app_name") or "").strip()
        machine_code = (data.get("machine_code") or "").strip()
        expires_at = (data.get("expires_at") or "").strip()
        if not app_name:
            return _error("app_name is required")
        if not machine_code:
            return _error("machine_code is required")
        if not expires_at:
            return _error("expires_at is required")

        try:
            issued = issue_offline_license(
                app,
                app_name=app_name,
                machine_code=machine_code,
                expires_at=expires_at,
                license_type=(data.get("license_type") or "paid").strip() or "paid",
                customer_name=(data.get("customer_name") or "").strip(),
                notes=(data.get("notes") or "").strip(),
                created_by="admin_api",
                client_ip=request.remote_addr or "",
                user_agent=request.headers.get("User-Agent") or "",
            )
            return _ok(issued)
        except ValueError as exc:
            return _error(str(exc), 400)

    @app.post("/api/v1/licenses/latest")
    def latest_license():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _error("JSON object required")
        try:
            issued = fetch_latest_license(
                app, app_name=data.get("app_name"), machine_code=data.get("machine_code"),
                challenge=data.get("challenge"), signature=data.get("signature"),
            )
        except ValueError as exc:
            return _error(str(exc), 400)
        except PermissionError as exc:
            return _error(str(exc), 403)
        if not issued:
            return _error("no active license", 404)
        return _ok(issued)

    @app.post("/api/v1/devices/register")
    def admin_register_device():
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _error("JSON object required")
        try:
            register_device(
                app, app_name=data.get("app_name"), machine_code=data.get("machine_code"),
                device_public_key=data.get("device_public_key"),
                challenge=data.get("challenge"), signature=data.get("signature"),
            )
        except ValueError as exc:
            return _error(str(exc), 400)
        except PermissionError as exc:
            return _error(str(exc), 403)
        return _ok({"registered": True})

    @app.post("/api/v1/devices/revoke")
    def admin_revoke_device():
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _error("JSON object required")
        try:
            revoked = revoke_device(
                app, app_name=data.get("app_name"), machine_code=data.get("machine_code"),
            )
        except ValueError as exc:
            return _error(str(exc), 400)
        if not revoked:
            return _error("device not enrolled", 404)
        return _ok({"revoked": True})

    @app.get("/api/v1/licenses/query")
    def query():
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error

        app_name = (request.args.get("app_name") or "").strip()
        machine_code = (request.args.get("machine_code") or "").strip()
        if not app_name:
            return _error("app_name is required")
        if not machine_code:
            return _error("machine_code is required")

        try:
            rows = query_licenses(app, app_name=app_name, machine_code=machine_code)
            return _ok({"items": rows})
        except ValueError as exc:
            return _error(str(exc), 400)

    @app.get("/api/v1/licenses/active_key")
    def admin_active_key():
        """管理端取设备当前有效授权码（复制发放用），不走设备签名。"""
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error
        app_name = (request.args.get("app_name") or "").strip()
        machine_code = (request.args.get("machine_code") or "").strip()
        if not app_name:
            return _error("app_name is required")
        if not machine_code:
            return _error("machine_code is required")
        try:
            row = fetch_active_license_key(app, app_name=app_name, machine_code=machine_code)
        except ValueError as exc:
            return _error(str(exc), 400)
        if not row:
            return _error("该设备当前没有有效授权码", 404)
        return _ok(row)

    @app.post("/api/v1/devices/forget")
    def admin_forget_device():
        """删除机器码全部记录（授权+设备凭证+挑战），测试设备可重新申请试用。"""
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _error("JSON object required")
        try:
            result = forget_machine(
                app, app_name=data.get("app_name"), machine_code=data.get("machine_code"),
            )
        except ValueError as exc:
            return _error(str(exc), 400)
        return _ok(result)

    @app.get("/api/v1/devices")
    def admin_list_devices():
        """设备列表（模糊搜索机器码/客户/备注）+ 首页统计摘要"""
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error
        q = (request.args.get("q") or "").strip()
        app_name = (request.args.get("app_name") or "").strip()
        return _ok(list_devices(app, q=q, app_name=app_name))

    @app.patch("/api/v1/devices")
    def admin_update_device():
        """编辑设备档案（客户名/备注）"""
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error
        data = request.get_json(silent=True) or {}
        try:
            return _ok(update_device_meta(
                app,
                app_name=(data.get("app_name") or "").strip(),
                machine_code=(data.get("machine_code") or "").strip(),
                customer_name=data.get("customer_name"),
                notes=data.get("notes"),
            ))
        except ValueError as exc:
            return _error(str(exc), 400)

    @app.get("/api/v1/stats")
    def stats():
        auth_error = _require_admin_token(app)
        if auth_error:
            return auth_error
        return _ok(license_stats(app))

    return app
