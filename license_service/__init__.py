from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .config import Config
from .crypto import ensure_keypair
from .db import init_db
from .service import issue_offline_license, issue_trial_license, query_licenses, renew_license


def _error(message, status_code=400):
    return jsonify({"ok": False, "error": message}), status_code


def _ok(data=None):
    return jsonify({"ok": True, "data": data or {}})


def _require_admin_token(app):
    configured = app.config.get("ADMIN_TOKEN") or ""
    incoming = (request.headers.get("X-Admin-Token") or "").strip()
    if not configured:
        return _error("admin token is not configured", 500)
    if incoming != configured:
        return _error("unauthorized", 401)
    return None


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    static_dir = Path(__file__).resolve().parent / "static"

    @app.get("/admin")
    def admin_page():
        return send_from_directory(static_dir, "admin.html")

    @app.get("/admin/<path:filename>")
    def admin_static(filename):
        return send_from_directory(static_dir, filename)

    ensure_keypair(app.config["PRIVATE_KEY_PATH"], app.config["PUBLIC_KEY_PATH"])
    init_db(app.config["DATABASE_PATH"])

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

    @app.post("/api/v1/trial/apply")
    def apply_trial():
        data = request.get_json(silent=True) or {}
        app_name = (data.get("app_name") or "").strip()
        machine_code = (data.get("machine_code") or "").strip()
        app_version = (data.get("app_version") or "").strip()
        if not app_name:
            return _error("app_name is required")
        if not machine_code:
            return _error("machine_code is required")
        try:
            issued = issue_trial_license(
                app,
                app_name=app_name,
                machine_code=machine_code,
                app_version=app_version,
                client_ip=request.remote_addr or "",
                user_agent=request.headers.get("User-Agent") or "",
            )
            return _ok(issued)
        except ValueError as exc:
            return _error(str(exc), 400)
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

    return app
