import datetime as dt
import uuid

from .crypto import (
    TOKEN_PREFIXES,
    hash_license_token,
    hash_machine_code,
    normalize_machine_code,
    sign_license_payload,
)
from .db import connect_db, execute, fetch_all


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
    conn=None,
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
    license_token = sign_license_payload(payload, config["PRIVATE_KEY_PATH"], app_name=app_name)
    license_token_hash = hash_license_token(license_token)

    insert_sql = """
        INSERT INTO license_issues(
            issue_id, app_name, machine_code_hash, machine_code_last4, license_type,
            channel, status, issued_at, expires_at, customer_name, notes,
            previous_issue_id, created_by, client_ip, user_agent, app_version,
            license_token, license_token_hash, updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
        """
    insert_args = [
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
    ]
    if conn is None:
        execute(config["DATABASE_PATH"], insert_sql, insert_args)
    else:
        conn.execute(insert_sql, insert_args)
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
        conn=conn,
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
    if app_name not in app.config["ALLOWED_APP_NAMES"] or app_name not in TOKEN_PREFIXES:
        raise ValueError("unsupported app_name")


def issue_trial_license(app, *, app_name, machine_code, trial_days=None, app_version="", client_ip="", user_agent=""):
    validate_app_name(app, app_name)
    maximum = app.config["TRIAL_DAYS_MAP"].get(app_name, app.config["TRIAL_DAYS"])
    if maximum < 1:
        raise ValueError("trial days must be positive")
    requested = trial_days if type(trial_days) is int and trial_days > 0 else maximum
    days = min(requested, maximum)
    machine_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        # Serialize claim lookup and issue insertion across workers and processes.
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            """SELECT issued_at, expires_at FROM license_issues
               WHERE app_name=? AND machine_code_hash=? AND channel='trial_auto'
               ORDER BY id ASC LIMIT 1""",
            (app_name, machine_hash),
        ).fetchone()
        today = dt.datetime.now(dt.timezone.utc).date()
        if existing:
            first_date = dt.datetime.fromisoformat(existing["issued_at"].replace("Z", "")).date()
            expires_date = _parse_date(existing["expires_at"])
            if today > expires_date:
                raise RuntimeError("trial expired")
            # A retry inherits the original deadline even if policy was changed later.
            days = (expires_date - first_date).days
        else:
            expires_date = today + dt.timedelta(days=days)
        issued = _issue_record(
            app, app_name=app_name, machine_code=machine_code, license_type="trial",
            expires_at=expires_date.isoformat(), channel="trial_auto",
            notes="auto trial", created_by="public_api", client_ip=client_ip,
            user_agent=user_agent, app_version=app_version, conn=conn,
        )
        conn.commit()
        issued["trial_days"] = days
        return issued
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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


def license_stats(app):
    current_date = dt.date.today()
    today = current_date.isoformat()
    cutoff = (current_date + dt.timedelta(days=30)).isoformat()
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN")
        overview = dict(conn.execute(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(CASE WHEN status='active' AND expires_at>=? THEN 1 ELSE 0 END), 0) AS active,
                      COALESCE(SUM(CASE WHEN expires_at<? THEN 1 ELSE 0 END), 0) AS expired,
                      COALESCE(SUM(CASE WHEN status='active' AND expires_at BETWEEN ? AND ? THEN 1 ELSE 0 END), 0) AS expiring_30d,
                      COUNT(DISTINCT machine_code_hash) AS unique_machines
               FROM license_issues""",
            (today, today, today, cutoff),
        ).fetchone())

        def grouped(field, expression, where="", args=(), limit=""):
            rows = conn.execute(
                f"""SELECT {expression} AS {field}, COUNT(*) AS count
                    FROM license_issues {where}
                    GROUP BY {expression}
                    ORDER BY count DESC, {field} ASC {limit}""",
                args,
            ).fetchall()
            return [dict(row) for row in rows]

        detail_fields = (
            "app_name, customer_name, machine_code_last4, license_type, issued_at, expires_at"
        )
        expiring_soon = [
            dict(row) for row in conn.execute(
                f"""SELECT {detail_fields} FROM license_issues
                    WHERE status='active' AND expires_at BETWEEN ? AND ?
                    ORDER BY expires_at ASC, id ASC LIMIT 20""",
                (today, cutoff),
            ).fetchall()
        ]
        recent_issues = [
            dict(row) for row in conn.execute(
                f"""SELECT {detail_fields}, channel, created_by FROM license_issues
                    ORDER BY id DESC LIMIT 20"""
            ).fetchall()
        ]
        monthly_trend = [
            dict(row) for row in conn.execute(
                """SELECT month, COUNT(*) AS count
                   FROM (SELECT strftime('%Y-%m', issued_at) AS month FROM license_issues)
                   WHERE month IS NOT NULL
                   GROUP BY month ORDER BY month ASC"""
            ).fetchall()
        ]
        return {
            "overview": overview,
            "app_distribution": grouped("app_name", "app_name"),
            "type_distribution": grouped("license_type", "license_type"),
            "channel_distribution": grouped("channel", "channel"),
            "creator_distribution": grouped("created_by", "created_by"),
            "customer_distribution": grouped(
                "customer_name", "customer_name",
                "WHERE customer_name IS NOT NULL AND customer_name!=''", limit="LIMIT 8",
            ),
            "status_distribution": grouped(
                "status", "CASE WHEN status='active' AND expires_at<:today THEN 'expired' ELSE status END",
                args={"today": today},
            ),
            "monthly_trend": monthly_trend,
            "expiring_soon": expiring_soon,
            "recent_issues": recent_issues,
        }
    finally:
        conn.close()


def write_audit_log(app, *, action, actor="", app_name="", machine_code_hash="", issue_id="", client_ip="", detail="", conn=None):
    sql = """
        INSERT INTO audit_logs(action, actor, app_name, machine_code_hash, issue_id, client_ip, detail)
        VALUES(?,?,?,?,?,?,?)
        """
    args = [action, actor, app_name, machine_code_hash, issue_id, client_ip, detail]
    if conn is None:
        execute(app.config["DATABASE_PATH"], sql, args)
    else:
        conn.execute(sql, args)
