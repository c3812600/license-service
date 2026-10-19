import datetime as dt
import re
import uuid

from .crypto import (
    TOKEN_PREFIXES,
    hash_license_token,
    hash_machine_code,
    normalize_machine_code,
    sign_license_payload,
)
from .device_auth import check_machine_code, decode_public_key, device_key, verify_proof
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
    # 设备档案 upsert（列表/搜索/客户信息载体；trial/renew/offline 统一在此建档）
    try:
        touch_device(app, app_name=app_name, machine_code=normalized_machine_code,
                     customer_name=customer_name, notes=notes, conn=conn)
    except Exception as _e:  # 档案失败不阻断签发（主流程已落库）
        import traceback; traceback.print_exc()

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


def issue_trial_license(
    app, *, app_name, machine_code, device_public_key, challenge, signature,
    trial_days=None, app_version="", client_ip="", user_agent="",
):
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    if not re.fullmatch(r"[A-F0-9]{64}", machine_code):
        raise ValueError("self-service trial requires a SHA-256 machine_code")
    public_key = decode_public_key(device_public_key)
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
        registered = device_key(conn, app_name, machine_hash)
        if registered and registered["revoked"]:
            raise PermissionError("device credential revoked")
        if registered and registered["public_key"] != public_key:
            raise PermissionError("device credential mismatch")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_hash=machine_hash,
            action="trial", challenge=challenge, signature=signature, public_key=public_key,
        )
        existing = conn.execute(
            """SELECT issued_at, expires_at FROM license_issues
               WHERE app_name=? AND machine_code_hash=? AND channel='trial_auto'
               ORDER BY id ASC LIMIT 1""",
            (app_name, machine_hash),
        ).fetchone()
        if not registered:
            prior = conn.execute(
                "SELECT 1 FROM license_issues WHERE app_name=? AND machine_code_hash=? LIMIT 1",
                (app_name, machine_hash),
            ).fetchone()
            if prior:
                raise RuntimeError("device enrollment requires admin approval")
            conn.execute(
                """INSERT INTO device_credentials(app_name, machine_code_hash, public_key)
                   VALUES(?,?,?)""",
                (app_name, machine_hash, public_key),
            )
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
    supersede=False,
):
    validate_app_name(app, app_name)
    _parse_date(expires_at)
    if supersede:
        # 客户端取"最长有效期"的 active 授权——缩短有效期必须先吊销旧记录，否则新记录永不生效
        machine_code = check_machine_code(machine_code)
        machine_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
        conn = connect_db(app.config["DATABASE_PATH"])
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE license_issues SET status='revoked' WHERE app_name=? AND machine_code_hash=? AND status='active'",
                [app_name, machine_hash],
            )
            write_audit_log(
                app, action="supersede_revoke", actor=created_by, app_name=app_name,
                machine_code_hash=machine_hash,
                detail="revoked %d active license(s) before renew to %s" % (cur.rowcount, expires_at),
                conn=conn,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
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


def fetch_latest_license(app, *, app_name, machine_code, challenge, signature):
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    machine_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        registered = device_key(conn, app_name, machine_hash)
        if not registered or registered["revoked"]:
            raise PermissionError("device not enrolled or revoked")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_hash=machine_hash,
            action="latest", challenge=challenge, signature=signature,
            public_key=registered["public_key"],
        )
        row = conn.execute(
            """SELECT license_token AS license_key, expires_at, license_type,
                      channel, issue_id, issued_at FROM license_issues
               WHERE app_name=? AND machine_code_hash=? AND status='active'
                 AND expires_at>=? AND channel!='offline_manual'
               ORDER BY expires_at DESC, id DESC LIMIT 1""",
            (app_name, machine_hash, dt.datetime.now(dt.timezone.utc).date().isoformat()),
        ).fetchone()
        write_audit_log(
            app, action="fetch_latest", actor="device", app_name=app_name,
            machine_code_hash=machine_hash, issue_id=row["issue_id"] if row else "",
            detail="active" if row else "none", conn=conn,
        )
        conn.commit()
        return dict(row) if row else None
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def register_device(app, *, app_name, machine_code, device_public_key, challenge, signature):
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    public_key = decode_public_key(device_public_key)
    machine_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_hash=machine_hash,
            action="register", challenge=challenge, signature=signature, public_key=public_key,
        )
        conn.execute(
            """INSERT INTO device_credentials(app_name, machine_code_hash, public_key, revoked)
               VALUES(?,?,?,0)
               ON CONFLICT(app_name, machine_code_hash)
               DO UPDATE SET public_key=excluded.public_key, revoked=0, updated_at=CURRENT_TIMESTAMP""",
            (app_name, machine_hash, public_key),
        )
        write_audit_log(
            app, action="register_device", actor="admin_api", app_name=app_name,
            machine_code_hash=machine_hash, conn=conn,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def revoke_device(app, *, app_name, machine_code):
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    machine_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        with conn:
            updated = conn.execute(
                """UPDATE device_credentials SET revoked=1, updated_at=CURRENT_TIMESTAMP
                   WHERE app_name=? AND machine_code_hash=?""",
                (app_name, machine_hash),
            ).rowcount
            if updated:
                write_audit_log(
                    app, action="revoke_device", actor="admin_api", app_name=app_name,
                    machine_code_hash=machine_hash, conn=conn,
                )
        return bool(updated)
    finally:
        conn.close()


def touch_device(app, *, app_name, machine_code, customer_name="", notes="", conn=None):
    """设备档案 upsert：所有签发入口（试用/续期/离线/注册）收到机器码即建档。
    customer_name/notes 仅在非空时覆盖（保留既有客户信息）。"""
    machine_code = check_machine_code(machine_code)
    machine_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    own = conn is None  # 外部事务中复用连接（trial 通道），否则自开事务
    if own:
        conn = connect_db(app.config["DATABASE_PATH"])
    try:
        if own:
            conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO device_registry (app_name, machine_code_hash, machine_code,
                                         customer_name, notes, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_name, machine_code_hash) DO UPDATE SET
                last_seen = excluded.last_seen,
                customer_name = CASE WHEN ? != '' THEN ? ELSE customer_name END,
                notes = CASE WHEN ? != '' THEN ? ELSE notes END
            """,
            [app_name, machine_hash, machine_code, customer_name, notes, now, now,
             customer_name, customer_name, notes, notes],
        )
        if own:
            conn.commit()
    except Exception:
        if own:
            conn.rollback()
        raise
    finally:
        if own:
            conn.close()


def update_device_meta(app, *, app_name, machine_code, customer_name=None, notes=None):
    """编辑设备档案的客户名/备注（列表页维护客户信息）"""
    machine_code = check_machine_code(machine_code)
    machine_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            """
            UPDATE device_registry SET
                customer_name = COALESCE(?, customer_name),
                notes = COALESCE(?, notes)
            WHERE app_name = ? AND machine_code_hash = ?
            """,
            [customer_name, notes, app_name, machine_hash],
        )
        conn.commit()
        if cur.rowcount == 0:
            raise ValueError("设备档案不存在（该机器码尚未与服务器交互）")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {"updated": True}


def list_devices(app, *, q="", app_name=""):
    """设备列表（模糊搜索机器码/客户/备注）+ 每设备最新有效授权 + 首页统计"""
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        rows = conn.execute(
            "SELECT * FROM device_registry ORDER BY last_seen DESC"
        ).fetchall()
        out = []
        now_date = dt.datetime.now(dt.timezone.utc).date()
        for row in rows:
            if app_name and row["app_name"] != app_name:
                continue
            latest = conn.execute(
                """
                SELECT expires_at, status FROM license_issues
                WHERE app_name = ? AND machine_code_hash = ? AND status = 'active'
                ORDER BY expires_at DESC LIMIT 1
                """,
                [row["app_name"], row["machine_code_hash"]],
            ).fetchone()
            expires = latest["expires_at"] if latest else None
            if expires:
                try:
                    expired = dt.datetime.strptime(expires[:10], "%Y-%m-%d").date() < now_date
                except ValueError:
                    expired = False
                state = "expired" if expired else "active"
            else:
                state = "none"
            out.append({
                "app_name": row["app_name"],
                "machine_code": row["machine_code"],
                "customer_name": row["customer_name"],
                "notes": row["notes"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "expires_at": expires,
                "license_state": state,
            })
        # 模糊搜索（机器码/客户/备注，大小写不敏感）
        if q:
            ql = q.lower()
            out = [d for d in out if ql in d["machine_code"].lower()
                   or ql in d["customer_name"].lower()
                   or ql in d["notes"].lower()]
        today = now_date
        soon = today + dt.timedelta(days=30)
        summary = {
            "total": len(out),
            "active": sum(1 for d in out if d["license_state"] == "active"
                          and d["expires_at"] and d["expires_at"][:10] > soon.isoformat()),
            "expiring_soon": sum(1 for d in out if d["license_state"] == "active"
                                 and d["expires_at"] and today.isoformat() <= d["expires_at"][:10] <= soon.isoformat()),
            "expired": sum(1 for d in out if d["license_state"] == "expired"),
        }
        return {"devices": out, "summary": summary}
    finally:
        conn.close()


def forget_machine(app, *, app_name, machine_code):
    """删除某机器码的全部记录（授权 + 设备凭证 + 未用挑战），
    让测试设备以"全新机器"重新申请试用/enrollment。管理端专用。"""
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    machine_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        cred = conn.execute(
            "DELETE FROM device_credentials WHERE app_name=? AND machine_code_hash=?",
            [app_name, machine_hash],
        )
        issues = conn.execute(
            "DELETE FROM license_issues WHERE app_name=? AND machine_code_hash=?",
            [app_name, machine_hash],
        )
        chall = conn.execute(
            "DELETE FROM device_challenges WHERE app_name=? AND machine_code_hash=?",
            [app_name, machine_hash],
        )
        write_audit_log(
            app, action="forget_machine", actor="admin_api", app_name=app_name,
            machine_code_hash=machine_hash,
            detail="removed %d licenses" % issues.rowcount, conn=conn,
        )
        conn.commit()
        return {
            "removed_issues": issues.rowcount,
            "removed_credential": cred.rowcount > 0,
            "removed_challenges": chall.rowcount,
        }
    except Exception:
        conn.rollback()
        raise
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
