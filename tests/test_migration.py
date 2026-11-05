"""数据库 schema 迁移测试。

迁移逻辑只在 `license_service/db.py` 里，与业务代码解耦；测试本身仍通过
`license_service` 包导入，因此运行前需装好项目依赖（flask / cryptography）：

    python -m unittest tests.test_migration -v
"""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from license_service.db import SCHEMA_VERSION, init_db


# v0 结构：device_challenges.expires_at 存 Unix 秒，与 license_issues.expires_at（日期文本）同名
LEGACY_SCHEMA = """
CREATE TABLE device_challenges (
    challenge TEXT PRIMARY KEY,
    app_name TEXT NOT NULL,
    machine_code_hash TEXT NOT NULL,
    action TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX idx_device_challenges_expiry ON device_challenges(expires_at);
"""


def _columns(db_path, table):
    with closing(sqlite3.connect(db_path)) as conn:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _user_version(db_path):
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute("PRAGMA user_version").fetchone()[0]


class SchemaMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "migration.db"

    def test_fresh_database_uses_renamed_column(self):
        init_db(self.db)

        columns = _columns(self.db, "device_challenges")
        self.assertIn("expires_at_epoch", columns)
        self.assertNotIn("expires_at", columns)
        self.assertEqual(_user_version(self.db), SCHEMA_VERSION)

    def test_legacy_database_is_migrated_and_keeps_rows(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.executescript(LEGACY_SCHEMA)
            conn.execute(
                "INSERT INTO device_challenges VALUES ('c' || 'A' * 42, 'ControlCommand', 'hash', 'trial', 1234)"
            )
            conn.commit()

        init_db(self.db)

        columns = _columns(self.db, "device_challenges")
        self.assertIn("expires_at_epoch", columns)
        self.assertNotIn("expires_at", columns)
        self.assertEqual(_user_version(self.db), SCHEMA_VERSION)

        with closing(sqlite3.connect(self.db)) as conn:
            row = conn.execute(
                "SELECT app_name, action, expires_at_epoch FROM device_challenges"
            ).fetchone()
            self.assertEqual(row, ("ControlCommand", "trial", 1234))
            # 旧索引随列改名由 SQLite 自动改写，仍指向新列
            indexes = {r[1] for r in conn.execute("PRAGMA index_list(device_challenges)")}
            self.assertIn("idx_device_challenges_expiry", indexes)
            indexed_columns = [
                r[2] for r in conn.execute("PRAGMA index_info(idx_device_challenges_expiry)")
            ]
            self.assertEqual(indexed_columns, ["expires_at_epoch"])

    def test_migration_is_idempotent(self):
        init_db(self.db)
        init_db(self.db)

        self.assertEqual(_user_version(self.db), SCHEMA_VERSION)
        self.assertIn("expires_at_epoch", _columns(self.db, "device_challenges"))

    def test_existing_new_schema_is_left_untouched(self):
        init_db(self.db)
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute(
                "INSERT INTO device_challenges VALUES ('c' || 'B' * 42, 'ControlCommand', 'hash', 'latest', 999)"
            )
            conn.commit()

        init_db(self.db)

        with closing(sqlite3.connect(self.db)) as conn:
            row = conn.execute("SELECT action, expires_at_epoch FROM device_challenges").fetchone()
            self.assertEqual(row, ("latest", 999))


    def test_v1_database_gains_activation_codes(self):
        """v1 库升级到 v2：新增 activation_codes 表，版本号推进，业务数据不受影响。"""
        init_db(self.db)
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("DROP TABLE activation_codes")
            conn.execute("PRAGMA user_version = 1")
            conn.commit()

        init_db(self.db)

        with closing(sqlite3.connect(self.db)) as conn:
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            self.assertEqual(
                conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION
            )
        self.assertIn("activation_codes", tables)
        self.assertIn("device_challenges", tables)

    def test_v2_database_gains_transfer_count(self):
        """v2 库升级到 v3：license_issues 新增 transfer_count，旧行回填 0。"""
        v2_license_issues = """
        CREATE TABLE license_issues (
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
        );
        """
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute(v2_license_issues)
            conn.execute(
                """INSERT INTO license_issues(
                       issue_id, app_name, machine_code_hash, license_type, channel,
                       issued_at, expires_at, license_token, license_token_hash)
                   VALUES ('i1', 'ControlCommand', 'h', 'paid', 'admin_renew',
                           '2026-01-01T00:00:00Z', '2030-01-01', 'tok', 'hash1')"""
            )
            conn.execute("PRAGMA user_version = 2")
            conn.commit()

        self.assertNotIn("transfer_count", _columns(self.db, "license_issues"))
        init_db(self.db)

        self.assertIn("transfer_count", _columns(self.db, "license_issues"))
        self.assertEqual(_user_version(self.db), SCHEMA_VERSION)
        with closing(sqlite3.connect(self.db)) as conn:
            value = conn.execute(
                "SELECT transfer_count FROM license_issues WHERE issue_id='i1'"
            ).fetchone()[0]
        self.assertEqual(value, 0)

    def test_v3_database_gains_recovery_codes(self):
        """v3 库升级到 v4：新增 recovery_codes 表，版本号推进。"""
        init_db(self.db)
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("DROP TABLE recovery_codes")
            conn.execute("PRAGMA user_version = 3")
            conn.commit()

        init_db(self.db)

        with closing(sqlite3.connect(self.db)) as conn:
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        self.assertIn("recovery_codes", tables)
        self.assertIn("transfer_count", _columns(self.db, "license_issues"))


if __name__ == "__main__":
    unittest.main()
