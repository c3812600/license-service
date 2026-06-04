import datetime as dt
import uuid

from .crypto import (
    hash_license_token,
    hash_machine_code,
    normalize_machine_code,
    sign_license_payload,
)
from .db import execute, fetch_all, fetch_one


def _utc_now():
    return dt.datetime.utcnow().replace(microsecond=0)


def _parse_date(date_text):
    return dt.datetime.strptime(str(date_text or "").strip(), "%Y-%m-%d").date()


def _issue_record(
    app,
    *,
    app_name,
    machine_code,
    license_type,
    expires_at,
    channel,
    customer_name="",
    notes="",
    previous_issue_id="",
    created_by="system",
    client_ip="",
    user_agent="",
    app_version="",
):
    config = app.config
    normalized_machine_code = normalize_machine_code(machine_code)
    machine_code_hash = hash_machine_code(normalized_machine_code, config["MACHINE_CODE_SALT"])
    issue_id = uuid.uuid4().hex
    issued_at = _utc_now().isoformat() + "Z"
    payload = {
        "ver": 1,
        "issue_id": issue_id,
        "app_name": app_name,
        "machine_code": normalized_machine_code,
        "license_type": license_type,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "customer_name": customer_name,
        "notes": notes,
    }
    license_token = sign_license_payload(payload, config["PRIVATE_KEY_PATH"])
    license_token_hash = hash_license_token(license_token)

    execute(
        config["DATABASE_PATH"],
        """
        INSERT INTO license_issues(
            issue_id, app_name, machine_code_hash, machine_code_last4, license_type,
            channel, status, issued_at, expires_at, customer_name, notes,
            previous_issue_id, created_by, client_ip, user_agent, app_version,
            license_token, license_token_hash, updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
        """,
        [
            issue_id,
            app_name,
            machine_code_hash,
            normalized_machine_code[-4:],
            license_type,
            channel,
            "active",
            issued_at,
            expires_at,
            customer_name,
            notes,
            previous_issue_id,
            created_by,
            client_ip,
            user_agent,
            app_version,
            license_token,
            license_token_hash,
        ],
    )
    write_audit_log(
        app,
        action="issue_license",
        actor=created_by,
        app_name=app_name,
        machine_code_hash=machine_code_hash,
        issue_id=issue_id,
        client_ip=client_ip,
        detail="{channel}:{license_type}:{expires_at}".format(
            channel=channel,
            license_type=license_type,
            expires_at=expires_at,
        ),
    )
    return {
        "issue_id": issue_id,
        "license_key": license_token,
        "license_type": license_type,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "app_name": app_name,
        "machine_code_last4": normalized_machine_code[-4:],
        "channel": channel,
    }


def validate_app_name(app, app_name):
    if app_name not in app.config["ALLOWED_APP_NAMES"]:
        raise ValueError("unsupported app_name")


def ensure_trial_available(app, app_name, machine_code):
    validate_app_name(app, app_name)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    existing = fetch_one(
        app.config["DATABASE_PATH"],
        """
        SELECT issue_id FROM license_issues
        WHERE app_name=? AND machine_code_hash=? AND channel='trial_auto'
        LIMIT 1
        """,
        [app_name, machine_code_hash],
    )
    if existing:
        raise RuntimeError("trial already claimed")


def issue_trial_license(app, *, app_name, machine_code, app_version="", client_ip="", user_agent=""):
    ensure_trial_available(app, app_name, machine_code)
    expires_at = (dt.date.today() + dt.timedelta(days=app.config["TRIAL_DAYS"])).isoformat()
    return _issue_record(
        app,
        app_name=app_name,
        machine_code=machine_code,
        license_type="trial",
        expires_at=expires_at,
        channel="trial_auto",
        customer_name="",
        notes="1-year auto trial",
        previous_issue_id="",
        created_by="public_api",
        client_ip=client_ip,
        user_agent=user_agent,
        app_version=app_version,
    )


def renew_license(
    app,
    *,
    app_name,
    machine_code,
    expires_at,
    license_type="paid",
    customer_name="",
    notes="",
    previous_issue_id="",
    created_by="admin_api",
    client_ip="",
    user_agent="",
):
    validate_app_name(app, app_name)
    _parse_date(expires_at)
    return _issue_record(
        app,
        app_name=app_name,
        machine_code=machine_code,
        license_type=license_type,
        expires_at=expires_at,
        channel="admin_renew",
        customer_name=customer_name,
        notes=notes,
        previous_issue_id=previous_issue_id,
        created_by=created_by,
        client_ip=client_ip,
        user_agent=user_agent,
    )


def issue_offline_license(
    app,
    *,
    app_name,
    machine_code,
    expires_at,
    license_type="paid",
    customer_name="",
    notes="",
    created_by="admin_api",
    client_ip="",
    user_agent="",
):
    validate_app_name(app, app_name)
    _parse_date(expires_at)
    return _issue_record(
        app,
        app_name=app_name,
        machine_code=machine_code,
        license_type=license_type,
        expires_at=expires_at,
        channel="offline_manual",
        customer_name=customer_name,
        notes=notes,
        previous_issue_id="",
        created_by=created_by,
        client_ip=client_ip,
        user_agent=user_agent,
    )


def query_licenses(app, *, app_name, machine_code):
    validate_app_name(app, app_name)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    rows = fetch_all(
        app.config["DATABASE_PATH"],
        """
        SELECT issue_id, license_type, channel, status, issued_at, expires_at,
               customer_name, notes, previous_issue_id, machine_code_last4, created_at
        FROM license_issues
        WHERE app_name=? AND machine_code_hash=?
        ORDER BY id DESC
        """,
        [app_name, machine_code_hash],
    )
    return [dict(row) for row in rows]


def write_audit_log(app, *, action, actor="", app_name="", machine_code_hash="", issue_id="", client_ip="", detail=""):
    execute(
        app.config["DATABASE_PATH"],
        """
        INSERT INTO audit_logs(action, actor, app_name, machine_code_hash, issue_id, client_ip, detail)
        VALUES(?,?,?,?,?,?,?)
        """,
        [action, actor, app_name, machine_code_hash, issue_id, client_ip, detail],
    )
