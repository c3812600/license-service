import datetime as dt
import secrets
import sqlite3
import re
import uuid

from .crypto import (
    TOKEN_PREFIXES,
    hash_license_token,
    hash_machine_code,
    normalize_machine_code,
    sign_license_payload,
    verify_license_payload,
)
from .device_auth import check_machine_code, decode_public_key, device_key, verify_proof
from .errors import ConflictError, ForbiddenError, InputError, NotFoundError
from .db import connect_db, execute, fetch_all


def _utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)


def _today():
    """到期判据统一用 UTC 日历日（与签发口径一致，消除 8 小时边界双标）。
    客户端按本地日历日比较到期，边界残差是已知产品取舍，见 docs。"""
    return dt.datetime.now(dt.timezone.utc).date()


def _parse_date(date_text):
    try:
        return dt.datetime.strptime(str(date_text or "").strip(), "%Y-%m-%d").date()
    except ValueError:
        raise InputError("invalid date format, expected YYYY-MM-DD")


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
    transfer_count=0,
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
            previous_issue_id, transfer_count, created_by, client_ip, user_agent, app_version,
            license_token, license_token_hash, updated_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
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
        transfer_count,
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
    except Exception:  # 档案失败不阻断签发（主流程已落库）
        import logging
        logging.getLogger("license_service").warning("touch_device(upsert) failed", exc_info=True)

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
        raise InputError("unsupported app_name")


def issue_trial_license(
    app, *, app_name, machine_code, device_public_key, challenge, signature,
    trial_days=None, app_version="", client_ip="", user_agent="",
):
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    if not re.fullmatch(r"[A-F0-9]{64}", machine_code):
        raise InputError("self-service trial requires a SHA-256 machine_code")
    public_key = decode_public_key(device_public_key)
    maximum = app.config["TRIAL_DAYS_MAP"].get(app_name, app.config["TRIAL_DAYS"])
    if maximum < 1:
        raise InputError("trial days must be positive")
    requested = trial_days if type(trial_days) is int and trial_days > 0 else maximum
    days = min(requested, maximum)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        # Serialize claim lookup and issue insertion across workers and processes.
        conn.execute("BEGIN IMMEDIATE")
        registered = device_key(conn, app_name, machine_code_hash)
        if registered and registered["revoked"]:
            raise ForbiddenError("device credential revoked", "REVOKED")
        if registered and registered["public_key"] != public_key:
            raise ForbiddenError("device credential mismatch", "CONFLICT")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_code_hash=machine_code_hash,
            action="trial", challenge=challenge, signature=signature, public_key=public_key,
        )
        existing = conn.execute(
            """SELECT issued_at, expires_at FROM license_issues
               WHERE app_name=? AND machine_code_hash=? AND channel='trial_auto'
               ORDER BY id ASC LIMIT 1""",
            (app_name, machine_code_hash),
        ).fetchone()
        if not registered:
            prior = conn.execute(
                "SELECT 1 FROM license_issues WHERE app_name=? AND machine_code_hash=? LIMIT 1",
                (app_name, machine_code_hash),
            ).fetchone()
            if prior:
                raise ConflictError("device enrollment requires admin approval")
            conn.execute(
                """INSERT INTO device_credentials(app_name, machine_code_hash, public_key)
                   VALUES(?,?,?)
                   ON CONFLICT(app_name, machine_code_hash)
                   DO UPDATE SET public_key=excluded.public_key, revoked=0, updated_at=CURRENT_TIMESTAMP""",
                (app_name, machine_code_hash, public_key),
            )
        # P0-2: 已有付费/离线/续期授权的机器不得自助领试用（含已登记设备），防试用顶替付费
        non_trial = conn.execute(
            "SELECT 1 FROM license_issues WHERE app_name=? AND machine_code_hash=? AND channel!='trial_auto' LIMIT 1",
            (app_name, machine_code_hash),
        ).fetchone()
        if non_trial:
            raise ForbiddenError("machine already has paid/offline license; self-service trial not allowed", "CONFLICT")
        today = _today()
        if existing:
            first_date = dt.datetime.fromisoformat(existing["issued_at"].replace("Z", "")).date()
            expires_date = _parse_date(existing["expires_at"])
            if today > expires_date:
                raise ConflictError("trial expired", "EXPIRED")
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
    machine_code = check_machine_code(machine_code)
    if supersede:
        # 客户端取"最长有效期"的 active 授权——缩短有效期必须先吊销旧记录，否则新记录永不生效
        machine_code = check_machine_code(machine_code)
        machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
        conn = connect_db(app.config["DATABASE_PATH"])
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE license_issues SET status='revoked' WHERE app_name=? AND machine_code_hash=? AND status='active'",
                [app_name, machine_code_hash],
            )
            write_audit_log(
                app, action="supersede_revoke", actor=created_by, app_name=app_name,
                machine_code_hash=machine_code_hash,
                detail="revoked %d active license(s) before renew to %s" % (cur.rowcount, expires_at),
                conn=conn,
            )
            # P0-3: 吊销+签发同一事务，签发失败整体回滚，避免设备被清零
            result = _issue_record(
                app, app_name=app_name, machine_code=machine_code,
                license_type=license_type, expires_at=expires_at, channel="admin_renew",
                customer_name=customer_name, notes=notes, previous_issue_id=previous_issue_id,
                created_by=created_by, client_ip=client_ip, user_agent=user_agent, conn=conn,
            )
            conn.commit()
            return result
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
    machine_code = check_machine_code(machine_code)
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


def fetch_active_license_key(app, *, app_name, machine_code):
    """管理端取设备当前有效的完整授权码（人工复制发放用，含离线签发单）。"""
    validate_app_name(app, app_name)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    rows = fetch_all(
        app.config["DATABASE_PATH"],
        """
        SELECT issue_id, license_token AS license_key, license_type, channel, issued_at, expires_at
        FROM license_issues
        WHERE app_name=? AND machine_code_hash=? AND status='active' AND expires_at>=?
        ORDER BY CASE WHEN license_type='trial' THEN 1 ELSE 0 END, expires_at DESC, id DESC LIMIT 1
        """,
        [app_name, machine_code_hash, _today().isoformat()],
    )
    return dict(rows[0]) if rows else None


def license_stats(app):
    current_date = _today()
    today = current_date.isoformat()
    cutoff = (current_date + dt.timedelta(days=30)).isoformat()
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN")
        overview = dict(conn.execute(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(CASE WHEN status='active' AND expires_at>=? THEN 1 ELSE 0 END), 0) AS active,
                      COALESCE(SUM(CASE WHEN status='active' AND expires_at<? THEN 1 ELSE 0 END), 0) AS expired,
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
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        registered = device_key(conn, app_name, machine_code_hash)
        if not registered:
            raise ForbiddenError("device not enrolled or revoked", "LICENSE_REQUIRED")
        if registered["revoked"]:
            raise ForbiddenError("device not enrolled or revoked", "REVOKED")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_code_hash=machine_code_hash,
            action="latest", challenge=challenge, signature=signature,
            public_key=registered["public_key"],
        )
        # 客户端每次授权检查都刷新「最近出现」（检查即打卡；档案失败不阻断取授权）
        try:
            touch_device(app, app_name=app_name, machine_code=machine_code, conn=conn)
        except Exception:
            import logging
            logging.getLogger("license_service").warning("touch_device(last_seen) failed", exc_info=True)
        row = conn.execute(
            """SELECT license_token AS license_key, expires_at, license_type,
                      channel, issue_id, issued_at FROM license_issues
               WHERE app_name=? AND machine_code_hash=? AND status='active'
                 AND expires_at>=? AND channel!='offline_manual'
               ORDER BY CASE WHEN license_type='trial' THEN 1 ELSE 0 END, expires_at DESC, id DESC LIMIT 1""",
            (app_name, machine_code_hash, _today().isoformat()),
        ).fetchone()
        write_audit_log(
            app, action="fetch_latest", actor="device", app_name=app_name,
            machine_code_hash=machine_code_hash, issue_id=row["issue_id"] if row else "",
            detail="active" if row else "none", conn=conn,
        )
        conn.commit()
        return dict(row) if row else None
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _verify_rotation_license(app, conn, *, license_key, app_name, machine_code, machine_code_hash):
    """持证换钥的凭证核验：授权码签名/绑定/有效期 + 吊销不复活 + 每机每日限频。"""
    payload = verify_license_payload(
        license_key, app.config["PUBLIC_KEY_PATH"], app_name=app_name,
    )
    if payload.get("app_name") != app_name:
        raise ForbiddenError("license_key app mismatch", "PRODUCT_MISMATCH")
    if normalize_machine_code(payload.get("machine_code") or "") != normalize_machine_code(machine_code):
        raise ForbiddenError("license_key machine mismatch", "MACHINE_MISMATCH")
    if _parse_date(payload.get("expires_at") or "") < _today():
        raise ForbiddenError("license_key expired", "EXPIRED")
    existing = device_key(conn, app_name, machine_code_hash)
    if existing and existing["revoked"]:
        raise ForbiddenError("device credential revoked", "REVOKED")
    recent = conn.execute(
        """SELECT COUNT(*) FROM audit_logs
           WHERE action='device_rotate' AND app_name=? AND machine_code_hash=?
             AND created_at >= datetime('now', '-1 day')""",
        (app_name, machine_code_hash),
    ).fetchone()[0]
    if recent >= 3:
        raise ForbiddenError("rotation rate limit exceeded, retry tomorrow", "ACTIVATION_LIMIT")


def register_device(app, *, app_name, machine_code, device_public_key, challenge, signature, license_key=""):
    """登记/更换设备公钥。两种授权等价：管理端 X-Admin-Token（路由层校验），
    或「持证换钥」——客户端持本机有效授权码自证归属（license_key），免管理员、限频、审计可溯。"""
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    public_key = decode_public_key(device_public_key)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        actor = "admin_api"
        action = "register_device"
        if license_key:
            actor = "device_rotate"
            action = "device_rotate"
            _verify_rotation_license(
                app, conn, license_key=license_key, app_name=app_name,
                machine_code=machine_code, machine_code_hash=machine_code_hash,
            )
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_code_hash=machine_code_hash,
            action="register", challenge=challenge, signature=signature, public_key=public_key,
        )
        conn.execute(
            """INSERT INTO device_credentials(app_name, machine_code_hash, public_key, revoked)
               VALUES(?,?,?,0)
               ON CONFLICT(app_name, machine_code_hash)
               DO UPDATE SET public_key=excluded.public_key, revoked=0, updated_at=CURRENT_TIMESTAMP""",
            (app_name, machine_code_hash, public_key),
        )
        write_audit_log(
            app, action=action, actor=actor, app_name=app_name,
            machine_code_hash=machine_code_hash, conn=conn,
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
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        with conn:
            updated = conn.execute(
                """UPDATE device_credentials SET revoked=1, updated_at=CURRENT_TIMESTAMP
                   WHERE app_name=? AND machine_code_hash=?""",
                (app_name, machine_code_hash),
            ).rowcount
            if updated:
                write_audit_log(
                    app, action="revoke_device", actor="admin_api", app_name=app_name,
                    machine_code_hash=machine_code_hash, conn=conn,
                )
        return bool(updated)
    finally:
        conn.close()


def touch_device(app, *, app_name, machine_code, customer_name="", notes="", conn=None):
    """设备档案 upsert：所有签发入口（试用/续期/离线/注册）收到机器码即建档。
    customer_name/notes 仅在非空时覆盖（保留既有客户信息）。"""
    machine_code = check_machine_code(machine_code)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
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
            [app_name, machine_code_hash, machine_code, customer_name, notes, now, now,
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
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
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
            [customer_name, notes, app_name, machine_code_hash],
        )
        conn.commit()
        if cur.rowcount == 0:
            raise NotFoundError("设备档案不存在（该机器码尚未与服务器交互）")
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
        now_date = _today()
        rows = conn.execute(
            """
            SELECT r.app_name, r.machine_code, r.customer_name, r.notes,
                   r.first_seen, r.last_seen,
                   (SELECT l.expires_at FROM license_issues l
                     WHERE l.app_name=r.app_name AND l.machine_code_hash=r.machine_code_hash
                       AND l.status='active'
                     ORDER BY CASE WHEN l.license_type='trial' THEN 1 ELSE 0 END,
                              l.expires_at DESC, l.id DESC LIMIT 1) AS expires_at
            FROM device_registry r
            WHERE (? = '' OR r.app_name = ?)
            ORDER BY r.last_seen DESC
            """,
            [app_name, app_name],
        ).fetchall()
        out = []
        for row in rows:
            expires = row["expires_at"]
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
        # 统计独立于搜索条件（不随 q 变），基于 app_name 过滤后的全集
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
        # 模糊搜索（机器码/客户/备注，大小写不敏感）——仅影响展示，不影响统计
        if q:
            ql = q.lower()
            out = [d for d in out if ql in d["machine_code"].lower()
                   or ql in d["customer_name"].lower()
                   or ql in d["notes"].lower()]
        return {"devices": out, "summary": summary}
    finally:
        conn.close()


def forget_device(app, *, app_name, machine_code):
    """删除某机器码的全部记录（授权 + 设备凭证 + 未用挑战），
    让测试设备以"全新机器"重新申请试用/enrollment。管理端专用。
    审计动作名沿用历史值 `forget_machine`，避免已落库的审计记录被割裂。"""
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])
    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        cred = conn.execute(
            "DELETE FROM device_credentials WHERE app_name=? AND machine_code_hash=?",
            [app_name, machine_code_hash],
        )
        issues = conn.execute(
            "DELETE FROM license_issues WHERE app_name=? AND machine_code_hash=?",
            [app_name, machine_code_hash],
        )
        chall = conn.execute(
            "DELETE FROM device_challenges WHERE app_name=? AND machine_code_hash=?",
            [app_name, machine_code_hash],
        )
        conn.execute(
            "DELETE FROM device_registry WHERE app_name=? AND machine_code_hash=?",
            [app_name, machine_code_hash],
        )
        write_audit_log(
            app, action="forget_machine", actor="admin_api", app_name=app_name,
            machine_code_hash=machine_code_hash,
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


# ---------------------------------------------------------------------------
# 激活码（activate 通道）
# ---------------------------------------------------------------------------

_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # 去掉易混淆的 I/L/O/0/1
_CODE_GROUPS = 4
_CODE_GROUP_SIZE = 4
_CODE_LENGTH = _CODE_GROUPS * _CODE_GROUP_SIZE  # 16 字符 ≈ 80 bit


def normalize_activation_code(code):
    """去掉分隔符与大小写差异；长度或字符集不符即视为无效。"""
    compact = "".join(ch for ch in str(code or "").upper() if ch.isalnum())
    if len(compact) != _CODE_LENGTH or any(ch not in _CODE_ALPHABET for ch in compact):
        raise InputError("invalid activation code")
    return compact


def _format_activation_code(compact):
    return "-".join(
        compact[i:i + _CODE_GROUP_SIZE] for i in range(0, len(compact), _CODE_GROUP_SIZE)
    )


def _new_activation_code():
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))


def create_activation_codes(
    app, *, app_name, days, count=1, license_type="paid",
    customer_name="", notes="", expires_at="", created_by="admin_api",
):
    """批量生成一次性激活码：码可离线交付，兑换时才绑定设备并签发 Token。"""
    validate_app_name(app, app_name)
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3650:
        raise InputError("days must be an integer between 1 and 3650")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 100:
        raise InputError("count must be an integer between 1 and 100")
    if license_type not in ("paid", "trial"):
        raise InputError("invalid license_type")
    expires_text = ""
    if expires_at:
        expires_text = _parse_date(expires_at).isoformat()
        if _parse_date(expires_text) < _today():
            raise InputError("expires_at is in the past")

    conn = connect_db(app.config["DATABASE_PATH"])
    created = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        for _ in range(count):
            for _attempt in range(5):
                compact = _new_activation_code()
                try:
                    conn.execute(
                        """INSERT INTO activation_codes(
                               code, app_name, license_type, days, customer_name, notes,
                               status, expires_at, created_by)
                           VALUES(?,?,?,?,?,?,'issued',?,?)""",
                        (compact, app_name, license_type, days, customer_name, notes,
                         expires_text, created_by),
                    )
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                raise ConflictError("activation code generation collision", "INTERNAL")
            created.append(_format_activation_code(compact))
        write_audit_log(
            app, action="issue_activation_codes", actor=created_by, app_name=app_name,
            detail="count=%d days=%d" % (count, days), conn=conn,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "app_name": app_name,
        "days": days,
        "license_type": license_type,
        "expires_at": expires_text,
        "codes": created,
    }


def activate_with_code(
    app, *, app_name, machine_code, code, device_public_key, challenge, signature,
    client_ip="", user_agent="", app_version="",
):
    """兑换激活码：一次性核销 + 绑定设备公钥 + 签发 Token（同一事务）。"""
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    public_key = decode_public_key(device_public_key)
    compact = normalize_activation_code(code)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])

    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM activation_codes WHERE code=?", (compact,)
        ).fetchone()
        if row is None:
            raise InputError("invalid activation code")
        if row["app_name"] != app_name:
            raise InputError("activation code app mismatch", "PRODUCT_MISMATCH")
        if row["status"] == "used":
            raise InputError("activation code already used", "CONFLICT")
        if row["status"] != "issued":
            raise InputError("activation code is not redeemable", "CONFLICT")
        if row["expires_at"] and _parse_date(row["expires_at"]) < _today():
            raise InputError("activation code expired", "EXPIRED")

        registered = device_key(conn, app_name, machine_code_hash)
        if registered and registered["revoked"]:
            raise ForbiddenError("device credential revoked", "REVOKED")
        if registered and registered["public_key"] != public_key:
            raise ForbiddenError("device credential mismatch", "CONFLICT")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code,
            machine_code_hash=machine_code_hash, action="activate",
            challenge=challenge, signature=signature, public_key=public_key,
        )
        # 兑换即完成设备登记：后续 validate / latest 需要已登记的公钥
        conn.execute(
            """INSERT INTO device_credentials(app_name, machine_code_hash, public_key, revoked)
               VALUES(?,?,?,0)
               ON CONFLICT(app_name, machine_code_hash)
               DO UPDATE SET public_key=excluded.public_key, revoked=0,
                             updated_at=CURRENT_TIMESTAMP""",
            (app_name, machine_code_hash, public_key),
        )

        expires_at = (_today() + dt.timedelta(days=int(row["days"]))).isoformat()
        issued = _issue_record(
            app, app_name=app_name, machine_code=machine_code,
            license_type=row["license_type"], expires_at=expires_at,
            channel="activation_code", customer_name=row["customer_name"],
            notes=row["notes"], created_by="activation_code",
            client_ip=client_ip, user_agent=user_agent, app_version=app_version,
            conn=conn,
        )
        updated = conn.execute(
            """UPDATE activation_codes
                  SET status='used', used_at=?, used_machine_code_hash=?, issue_id=?
                WHERE code=? AND status='issued'""",
            (_utc_now().isoformat(), machine_code_hash, issued["issue_id"], compact),
        ).rowcount
        if updated != 1:
            raise ConflictError("activation code already redeemed", "CONFLICT")
        write_audit_log(
            app, action="activate", actor="device", app_name=app_name,
            machine_code_hash=machine_code_hash, issue_id=issued["issue_id"],
            client_ip=client_ip, detail="channel=activation_code", conn=conn,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {**issued, "activation_code": _format_activation_code(compact)}


def create_recovery_codes(
    app, *, app_name, machine_code, count=3, expires_at="", created_by="admin_api",
):
    """为设备当前有效授权生成一次性恢复码（§8.10）。

    设备私钥与 Token 双丢时的救命稻草：管理员签发后交由用户离线保管，
    兑换时重新绑定设备公钥（同机）或迁移到新机（异机）。
    """
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10:
        raise InputError("count must be an integer between 1 and 10")
    expires_text = ""
    if expires_at:
        expires_text = _parse_date(expires_at).isoformat()
        if _parse_date(expires_text) < _today():
            raise InputError("expires_at is in the past")
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])

    conn = connect_db(app.config["DATABASE_PATH"])
    created = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT issue_id FROM license_issues
               WHERE app_name=? AND machine_code_hash=? AND status='active' AND expires_at>=?
               ORDER BY CASE WHEN license_type='trial' THEN 1 ELSE 0 END, expires_at DESC, id DESC LIMIT 1""",
            (app_name, machine_code_hash, _today().isoformat()),
        ).fetchone()
        if row is None:
            raise NotFoundError("该设备当前没有有效授权码")
        issue_id = row["issue_id"]
        for _ in range(count):
            for _attempt in range(5):
                compact = _new_activation_code()
                try:
                    conn.execute(
                        """INSERT INTO recovery_codes(code, app_name, issue_id, status, expires_at, created_by)
                           VALUES(?,?,?,'issued',?,?)""",
                        (compact, app_name, issue_id, expires_text, created_by),
                    )
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                raise ConflictError("recovery code generation collision", "INTERNAL")
            created.append(_format_activation_code(compact))
        write_audit_log(
            app, action="issue_recovery_codes", actor=created_by, app_name=app_name,
            issue_id=issue_id, detail="count=%d" % count, conn=conn,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {"app_name": app_name, "issue_id": issue_id, "codes": created}


def recover_with_code(
    app, *, app_name, machine_code, code, device_public_key, challenge, signature,
    client_ip="", user_agent="", app_version="",
):
    """凭恢复码恢复授权：设备私钥与 Token 双丢时重新绑定（§8.10）。

    同机恢复：换绑设备公钥，原 Token 仍有效、原样返还（issue 不动）。
    异机恢复：等同换机迁移（解绑旧机 + 新机签发），但不占 transfer_count
    （恢复码本身就是管理员管控的出口，一码一次性）。
    """
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    public_key = decode_public_key(device_public_key)
    try:
        compact = normalize_activation_code(code)
    except ValueError:
        raise InputError("invalid recovery code")
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])

    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        code_row = conn.execute(
            "SELECT * FROM recovery_codes WHERE code=?", (compact,)
        ).fetchone()
        if code_row is None:
            raise InputError("invalid recovery code")
        if code_row["app_name"] != app_name:
            raise InputError("recovery code app mismatch", "PRODUCT_MISMATCH")
        if code_row["status"] == "used":
            raise InputError("recovery code already used", "CONFLICT")
        if code_row["status"] != "issued":
            raise InputError("recovery code is not redeemable", "CONFLICT")
        if code_row["expires_at"] and _parse_date(code_row["expires_at"]) < _today():
            raise InputError("recovery code expired", "EXPIRED")

        license_row = conn.execute(
            """SELECT machine_code_hash, license_type, status, expires_at,
                      customer_name, notes, transfer_count
               FROM license_issues WHERE issue_id=?""",
            (code_row["issue_id"],),
        ).fetchone()
        if license_row is None:
            raise NotFoundError("recovery target license not found")
        if license_row["status"] != "active":
            raise ForbiddenError("license is revoked", "REVOKED")
        if _parse_date(license_row["expires_at"]) < _today():
            raise ForbiddenError("license_key expired", "EXPIRED")

        # 恢复码即重绑授权：不校验旧公钥是否一致/是否停用——换钥/复活凭据正是本流程目的
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_code_hash=machine_code_hash,
            action="recover", challenge=challenge, signature=signature, public_key=public_key,
        )

        old_hash = license_row["machine_code_hash"]
        same_machine = old_hash == machine_code_hash
        if same_machine:
            # 同机恢复：只换绑公钥；Token 不换发，原样返还
            conn.execute(
                """INSERT INTO device_credentials(app_name, machine_code_hash, public_key, revoked)
                   VALUES(?,?,?,0)
                   ON CONFLICT(app_name, machine_code_hash)
                   DO UPDATE SET public_key=excluded.public_key, revoked=0, updated_at=CURRENT_TIMESTAMP""",
                (app_name, machine_code_hash, public_key),
            )
            token_row = conn.execute(
                "SELECT license_token FROM license_issues WHERE issue_id=?", (code_row["issue_id"],)
            ).fetchone()
            issued = {
                "issue_id": code_row["issue_id"],
                "license_key": token_row["license_token"],
                "license_type": license_row["license_type"],
                "expires_at": license_row["expires_at"],
                "app_name": app_name,
                "channel": "recovery_same",
            }
        else:
            # 异机恢复：解绑旧机 + 新机签发（迁移语义）
            conn.execute(
                """UPDATE license_issues SET status='revoked', updated_at=CURRENT_TIMESTAMP
                   WHERE app_name=? AND machine_code_hash=? AND status='active'""",
                (app_name, old_hash),
            )
            conn.execute(
                """UPDATE device_credentials SET revoked=1, updated_at=CURRENT_TIMESTAMP
                   WHERE app_name=? AND machine_code_hash=? AND revoked=0""",
                (app_name, old_hash),
            )
            conn.execute(
                """INSERT INTO device_credentials(app_name, machine_code_hash, public_key, revoked)
                   VALUES(?,?,?,0)
                   ON CONFLICT(app_name, machine_code_hash)
                   DO UPDATE SET public_key=excluded.public_key, revoked=0, updated_at=CURRENT_TIMESTAMP""",
                (app_name, machine_code_hash, public_key),
            )
            issued = _issue_record(
                app, app_name=app_name, machine_code=machine_code,
                license_type=license_row["license_type"], expires_at=license_row["expires_at"],
                channel="recovery", customer_name=license_row["customer_name"],
                notes=license_row["notes"], previous_issue_id=code_row["issue_id"],
                transfer_count=license_row["transfer_count"],
                created_by="recovery_code", client_ip=client_ip, user_agent=user_agent,
                app_version=app_version, conn=conn,
            )
        updated = conn.execute(
            """UPDATE recovery_codes
                  SET status='used', used_at=?, used_machine_code_hash=?
                WHERE code=? AND status='issued'""",
            (_utc_now().isoformat(), machine_code_hash, compact),
        ).rowcount
        if updated != 1:
            raise ConflictError("recovery code already redeemed", "CONFLICT")
        write_audit_log(
            app, action="recover", actor="device", app_name=app_name,
            machine_code_hash=machine_code_hash, issue_id=code_row["issue_id"],
            client_ip=client_ip,
            detail="channel=%s" % issued["channel"], conn=conn,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        **issued,
        "recovery_code": _format_activation_code(compact),
        "transfer_count": license_row["transfer_count"],
        "transfer_remaining": max(app.config["TRANSFER_LIMIT"] - license_row["transfer_count"], 0),
    }


def validate_license(app, *, app_name, machine_code, license_token, challenge, signature, client_ip=""):
    """设备签名的在线状态核查：返回 active / expired / revoked / unknown 与服务器时间。

    只在令牌签名、产品、机器码都与本机登记一致时才会查询状态；不返回新 Token。
    """
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])

    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        registered = device_key(conn, app_name, machine_code_hash)
        if not registered:
            raise ForbiddenError("device not enrolled or revoked", "LICENSE_REQUIRED")
        if registered["revoked"]:
            raise ForbiddenError("device not enrolled or revoked", "REVOKED")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code,
            machine_code_hash=machine_code_hash, action="validate",
            challenge=challenge, signature=signature,
            public_key=registered["public_key"],
        )
        payload = verify_license_payload(
            license_token, app.config["PUBLIC_KEY_PATH"], app_name=app_name
        )
        if payload.get("app_name") != app_name:
            raise ForbiddenError("license app mismatch", "PRODUCT_MISMATCH")
        if normalize_machine_code(payload.get("machine_code") or "") != machine_code:
            raise ForbiddenError("license machine mismatch", "MACHINE_MISMATCH")

        issue_id = str(payload.get("issue_id") or "")
        row = conn.execute(
            """SELECT status, expires_at, license_type, issued_at, channel
                 FROM license_issues WHERE issue_id=?""",
            (issue_id,),
        ).fetchone()
        if row is None:
            status = "unknown"
        elif row["status"] != "active":
            status = "revoked"
        elif _parse_date(row["expires_at"]) < _today():
            status = "expired"
        else:
            status = "active"

        write_audit_log(
            app, action="validate", actor="device", app_name=app_name,
            machine_code_hash=machine_code_hash, issue_id=issue_id,
            client_ip=client_ip, detail=status, conn=conn,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "status": status,
        "issue_id": issue_id,
        "expires_at": row["expires_at"] if row else str(payload.get("expires_at") or ""),
        "license_type": row["license_type"] if row else str(payload.get("license_type") or ""),
        "channel": row["channel"] if row else "",
        "server_time": _utc_now().isoformat() + "Z",
    }


def unbind_device(app, *, app_name, machine_code, created_by="admin_api"):
    """管理员解绑（换机场景）：吊销该机器全部 active 授权并停用设备凭据。

    与 forget_device 的区别：保留签发历史与设备档案，只做状态停用，可审计可回溯。
    """
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])

    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        revoked = conn.execute(
            """UPDATE license_issues SET status='revoked', updated_at=CURRENT_TIMESTAMP
                WHERE app_name=? AND machine_code_hash=? AND status='active'""",
            (app_name, machine_code_hash),
        ).rowcount
        credential = conn.execute(
            """UPDATE device_credentials SET revoked=1, updated_at=CURRENT_TIMESTAMP
                WHERE app_name=? AND machine_code_hash=? AND revoked=0""",
            (app_name, machine_code_hash),
        ).rowcount
        write_audit_log(
            app, action="unbind_device", actor=created_by, app_name=app_name,
            machine_code_hash=machine_code_hash,
            detail="revoked_issues=%d credential=%d" % (revoked, credential), conn=conn,
        )
        conn.commit()
        return {"revoked_issues": revoked, "credential_revoked": credential > 0}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def unbind_device_self(
    app, *, app_name, machine_code, challenge, signature, license_key,
    client_ip="", user_agent="",
):
    """自助解绑：持本机有效授权码 + 本机设备签名，停用本机授权（§8.8 自助模式）。

    与管理员 unbind 同效（吊销该机全部 active 授权 + 停用设备凭据），双因子
    （license_key 证授权归属、设备签名证机器控制权），销毁性、幂等、无需配额
    （迁移限次由 transfer_count 承担，见 §8.9）。
    """
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)
    payload = verify_license_payload(license_key, app.config["PUBLIC_KEY_PATH"], app_name=app_name)
    if payload.get("app_name") != app_name:
        raise ForbiddenError("license_key app mismatch", "PRODUCT_MISMATCH")
    if normalize_machine_code(payload.get("machine_code") or "") != machine_code:
        raise ForbiddenError("license_key machine mismatch", "MACHINE_MISMATCH")
    issue_id = str(payload.get("issue_id") or "")
    if not issue_id:
        raise InputError("license_key has no issue_id")
    machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])

    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT machine_code_hash FROM license_issues WHERE issue_id=?", (issue_id,)
        ).fetchone()
        if row is None or row["machine_code_hash"] != machine_code_hash:
            raise ForbiddenError("license_key machine mismatch", "MACHINE_MISMATCH")
        registered = device_key(conn, app_name, machine_code_hash)
        if not registered:
            raise ForbiddenError("device not enrolled or revoked", "LICENSE_REQUIRED")
        if registered["revoked"]:
            raise ForbiddenError("device not enrolled or revoked", "REVOKED")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_code_hash=machine_code_hash,
            action="unbind", challenge=challenge, signature=signature,
            public_key=registered["public_key"],
        )
        revoked = conn.execute(
            """UPDATE license_issues SET status='revoked', updated_at=CURRENT_TIMESTAMP
               WHERE app_name=? AND machine_code_hash=? AND status='active'""",
            (app_name, machine_code_hash),
        ).rowcount
        credential = conn.execute(
            """UPDATE device_credentials SET revoked=1, updated_at=CURRENT_TIMESTAMP
               WHERE app_name=? AND machine_code_hash=? AND revoked=0""",
            (app_name, machine_code_hash),
        ).rowcount
        write_audit_log(
            app, action="unbind_self", actor="device", app_name=app_name,
            machine_code_hash=machine_code_hash, issue_id=issue_id,
            client_ip=client_ip,
            detail="revoked_issues=%d credential=%d" % (revoked, credential), conn=conn,
        )
        conn.commit()
        return {"revoked_issues": revoked, "credential_revoked": credential > 0}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def transfer_license(
    app, *, app_name, machine_code, device_public_key, challenge, signature,
    license_key, client_ip="", user_agent="", app_version="",
):
    """自助换机：持旧机有效授权码 + 新机设备签名，把授权迁移到新机器（§8.9）。

    同一事务：核验授权与换机配额 → 解绑旧机（吊销其全部 active 授权与设备凭据）
    → 登记新机公钥 → 按旧授权的类型/有效期签发新 Token（previous_issue_id 串链）。
    换机次数按谱系计次（transfer_count 自上一环继承 +1），上限 TRANSFER_LIMIT。
    """
    validate_app_name(app, app_name)
    machine_code = check_machine_code(machine_code)  # 新机器码
    public_key = decode_public_key(device_public_key)  # 新机公钥
    payload = verify_license_payload(license_key, app.config["PUBLIC_KEY_PATH"], app_name=app_name)
    if payload.get("app_name") != app_name:
        raise ForbiddenError("license_key app mismatch", "PRODUCT_MISMATCH")
    old_machine = normalize_machine_code(payload.get("machine_code") or "")
    if not old_machine:
        raise InputError("license_key has no machine binding")
    if old_machine == machine_code:
        raise ConflictError("same machine: use device key rotation via register instead")
    issue_id = str(payload.get("issue_id") or "")
    if not issue_id:
        raise InputError("license_key has no issue_id")
    old_machine_code_hash = hash_machine_code(old_machine, app.config["MACHINE_CODE_SALT"])
    new_machine_code_hash = hash_machine_code(machine_code, app.config["MACHINE_CODE_SALT"])

    conn = connect_db(app.config["DATABASE_PATH"])
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT machine_code_hash, license_type, status, expires_at,
                      customer_name, notes, transfer_count
               FROM license_issues WHERE issue_id=?""",
            (issue_id,),
        ).fetchone()
        if row is None:
            raise InputError("license_key not found in records", "NOT_FOUND")
        if row["machine_code_hash"] != old_machine_code_hash:
            raise ForbiddenError("license_key machine mismatch", "MACHINE_MISMATCH")
        if row["status"] != "active":
            raise ForbiddenError("license_key is revoked", "REVOKED")
        if _parse_date(row["expires_at"]) < _today():
            raise ForbiddenError("license_key expired", "EXPIRED")

        limit = app.config["TRANSFER_LIMIT"]
        if not isinstance(limit, int) or limit < 1:
            raise RuntimeError("transfer limit misconfigured")
        if row["transfer_count"] >= limit:
            raise ForbiddenError("transfer limit exceeded, contact vendor", "ACTIVATION_LIMIT")

        registered = device_key(conn, app_name, new_machine_code_hash)
        if registered and registered["revoked"]:
            raise ForbiddenError("device credential revoked", "REVOKED")
        if registered and registered["public_key"] != public_key:
            raise ForbiddenError("device credential mismatch", "CONFLICT")
        verify_proof(
            conn, app_name=app_name, machine_code=machine_code, machine_code_hash=new_machine_code_hash,
            action="transfer", challenge=challenge, signature=signature, public_key=public_key,
        )

        # 解绑旧机：吊销全部 active 授权 + 停用设备凭据（换机即弃旧机）
        conn.execute(
            """UPDATE license_issues SET status='revoked', updated_at=CURRENT_TIMESTAMP
               WHERE app_name=? AND machine_code_hash=? AND status='active'""",
            (app_name, old_machine_code_hash),
        )
        conn.execute(
            """UPDATE device_credentials SET revoked=1, updated_at=CURRENT_TIMESTAMP
               WHERE app_name=? AND machine_code_hash=? AND revoked=0""",
            (app_name, old_machine_code_hash),
        )
        # 登记新机公钥（后续 latest/validate 需要）
        conn.execute(
            """INSERT INTO device_credentials(app_name, machine_code_hash, public_key, revoked)
               VALUES(?,?,?,0)
               ON CONFLICT(app_name, machine_code_hash)
               DO UPDATE SET public_key=excluded.public_key, revoked=0, updated_at=CURRENT_TIMESTAMP""",
            (app_name, new_machine_code_hash, public_key),
        )
        issued = _issue_record(
            app, app_name=app_name, machine_code=machine_code,
            license_type=row["license_type"], expires_at=row["expires_at"],
            channel="transfer", customer_name=row["customer_name"], notes=row["notes"],
            previous_issue_id=issue_id, transfer_count=row["transfer_count"] + 1,
            created_by="transfer_api", client_ip=client_ip, user_agent=user_agent,
            app_version=app_version, conn=conn,
        )
        write_audit_log(
            app, action="license_transfer", actor="device", app_name=app_name,
            machine_code_hash=new_machine_code_hash, issue_id=issued["issue_id"],
            client_ip=client_ip,
            detail="from=%s to=%s transfer_count=%d" % (
                issue_id, issued["issue_id"], row["transfer_count"] + 1),
            conn=conn,
        )
        conn.commit()
        issued["transfer_count"] = row["transfer_count"] + 1
        issued["transfer_remaining"] = max(limit - issued["transfer_count"], 0)
        return issued
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
