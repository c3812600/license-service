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


if __name__ == "__main__":
    unittest.main()
