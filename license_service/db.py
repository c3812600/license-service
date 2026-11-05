import sqlite3
from pathlib import Path


SCHEMA_VERSION = 1


def connect_db(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _table_columns(conn, table):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn):
    """按 `PRAGMA user_version` 递增执行迁移；每步幂等，可重复调用。

    v0 -> v1：`device_challenges.expires_at`（Unix 秒）改名为 `expires_at_epoch`。
    该列与 `license_issues.expires_at`（日期文本）同名不同义，改名消除歧义；
    挑战行本身是短生命周期数据，改名不改变任何业务语义。
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema v{version} is newer than this build (v{SCHEMA_VERSION}); "
            "refusing to run migrations"
        )
    if version < 1:
        if sqlite3.sqlite_version_info < (3, 25, 0):
            raise RuntimeError(
                "schema migration to v1 requires SQLite >= 3.25 "
                f"(current {sqlite3.sqlite_version})"
            )
        columns = _table_columns(conn, "device_challenges")
        if "expires_at" in columns and "expires_at_epoch" not in columns:
            conn.execute(
                "ALTER TABLE device_challenges RENAME COLUMN expires_at TO expires_at_epoch"
            )
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def init_db(db_path):
    conn = connect_db(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS license_issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id TEXT NOT NULL UNIQUE,
                app_name TEXT NOT NULL,
                machine_code_hash TEXT NOT NULL,
                machine_code_last4 TEXT NOT NULL DEFAULT '',
                license_type TEXT NOT NULL,
                channel TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                customer_name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                previous_issue_id TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                app_version TEXT NOT NULL DEFAULT '',
                license_token TEXT NOT NULL,
                license_token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                app_name TEXT NOT NULL DEFAULT '',
                machine_code_hash TEXT NOT NULL DEFAULT '',
                issue_id TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_registry (
                app_name TEXT NOT NULL,
                machine_code_hash TEXT NOT NULL,
                machine_code TEXT NOT NULL,
                customer_name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (app_name, machine_code_hash)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_credentials (
                app_name TEXT NOT NULL,
                machine_code_hash TEXT NOT NULL,
                public_key BLOB NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (app_name, machine_code_hash)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_challenges (
                challenge TEXT PRIMARY KEY,
                app_name TEXT NOT NULL,
                machine_code_hash TEXT NOT NULL,
                action TEXT NOT NULL,
                expires_at_epoch INTEGER NOT NULL
            )
            """
        )
        # 表结构就位后再迁移旧库，最后统一建索引：
        # 旧库的 device_challenges 仍是 expires_at 列，先改名才能按新列建索引。
        _migrate(conn)
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_license_issues_machine
            ON license_issues(app_name, machine_code_hash)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_license_issues_type
            ON license_issues(license_type, status)
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_registry_last_seen ON device_registry(last_seen)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_challenges_expiry ON device_challenges(expires_at_epoch)"
        )
        conn.commit()
    finally:
        conn.close()


def fetch_all(db_path, query, args=()):
    conn = connect_db(db_path)
    try:
        cursor = conn.execute(query, args)
        return cursor.fetchall()
    finally:
        conn.close()


def execute(db_path, query, args=()):
    conn = connect_db(db_path)
    try:
        cursor = conn.execute(query, args)
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()
