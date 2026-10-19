import hmac
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .config import Config
from .crypto import ensure_keypair
from .db import init_db
from .device_auth import create_challenge
from .service import (
    fetch_latest_license, issue_offline_license, issue_trial_license, license_stats, forget_machine, query_licenses, register_device, renew_license, revoke_device, validate_app_name, list_devices, update_device_meta, touch_device,
)


def _error(message, status_code=400):
    return jsonify({"ok": False, "error": message}), status_code


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


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

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
