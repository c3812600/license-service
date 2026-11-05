#!/usr/bin/env python3
"""恢复演练：备份 -> 灾难模拟（库+密钥全丢）-> 恢复 -> 数据/迁移/服务/安全四重校验。

用法：
    python scripts/restore_drill.py            # 在仓库本地跑（临时目录，不碰生产数据）
    python scripts/restore_drill.py --keep     # 演练后保留临时目录供检查

生产环境按同样步骤做季度演练：备份用 scripts/backup_db.py，恢复单位必须是
**数据库 + keys/ed25519-{private,public}.pem 一体**——只恢复库、缺密钥时
服务会拒绝启动（安全设计，见 README「部署准备」）。本脚本就是该流程的
可重复验证，全部输出 PASS 才算演练通过。
"""

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from license_service.crypto import ensure_keypair  # noqa: E402
from license_service.db import SCHEMA_VERSION, init_db  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="license-service 恢复演练")
    parser.add_argument("--keep", action="store_true", help="演练后保留临时目录")
    args = parser.parse_args()

    drill = Path(tempfile.mkdtemp(prefix="license-restore-drill-"))
    db_dir = drill / "data"
    backup_dir = drill / "backups"
    key_dir = drill / "keys"
    key_backup = drill / "key-backup"
    for path in (db_dir, backup_dir):
        path.mkdir(parents=True)
    src_db = db_dir / "license-service.db"

    try:
        # 1. 建库 + 密钥（恢复点 = 库 + 密钥）
        init_db(str(src_db))
        ensure_keypair(str(key_dir / "priv.pem"), str(key_dir / "pub.pem"))
        key_backup.mkdir()
        shutil.copy2(key_dir / "priv.pem", key_backup / "priv.pem")
        shutil.copy2(key_dir / "pub.pem", key_backup / "pub.pem")
        conn = sqlite3.connect(str(src_db))
        conn.execute(
            """INSERT INTO license_issues(issue_id, app_name, machine_code_hash,
                   machine_code_last4, license_type, channel, status, issued_at,
                   expires_at, license_token, license_token_hash)
               VALUES('drill-i1','ControlCommand','hash-1','1234','paid','admin_renew',
                      'active','2026-01-01T00:00:00Z','2030-01-01','tok-1','tokhash-1')"""
        )
        conn.execute(
            """INSERT INTO device_registry(app_name, machine_code_hash, machine_code)
               VALUES('ControlCommand','hash-1','MACHINE-DRILL-1')"""
        )
        conn.commit()
        before_rows = conn.execute("SELECT COUNT(*) FROM license_issues").fetchone()[0]
        before_version = conn.execute("PRAGMA user_version").fetchone()[0]
        conn.close()
        print(f"[1] 建库 + 密钥完成: {before_rows} 行, schema v{before_version} (SCHEMA_VERSION={SCHEMA_VERSION})")

        # 2. 备份（与生产同一条命令）
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "backup_db.py"), str(src_db), str(backup_dir)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        backup_file = sorted(backup_dir.glob("*.db"))[-1]
        print(f"[2] 备份完成: {backup_file.name} ({backup_file.stat().st_size} bytes)")

        # 3. 备份体自检
        bconn = sqlite3.connect(str(backup_file))
        assert bconn.execute("SELECT COUNT(*) FROM license_issues").fetchone()[0] == before_rows
        assert bconn.execute("PRAGMA user_version").fetchone()[0] == before_version
        assert bconn.execute("SELECT issue_id FROM license_issues").fetchone()[0] == "drill-i1"
        bconn.close()
        print("[3] 备份体自检通过")

        # 4. 灾难：库（含 WAL/SHM）与密钥全丢
        for suffix in ("", "-wal", "-shm"):
            victim = Path(str(src_db) + suffix)
            if victim.exists():
                victim.unlink()
        shutil.rmtree(key_dir)
        print("[4] 已删除原库与密钥，模拟灾难")

        # 5. 恢复：库 + 密钥一体还原
        shutil.copy2(backup_file, src_db)
        shutil.copytree(key_backup, key_dir)
        print("[5] 恢复完成（库 + 密钥）")

        # 6. 数据校验
        rconn = sqlite3.connect(str(src_db))
        assert rconn.execute("SELECT COUNT(*) FROM license_issues").fetchone()[0] == before_rows
        row = rconn.execute(
            "SELECT issue_id, status, expires_at FROM license_issues"
        ).fetchone()
        assert row == ("drill-i1", "active", "2030-01-01")
        assert rconn.execute("SELECT machine_code FROM device_registry").fetchone()[0] == "MACHINE-DRILL-1"
        rconn.close()
        print(f"[6] 数据校验通过: 授权={row[0]}/{row[1]}/{row[2]}")

        # 7. init_db 幂等
        init_db(str(src_db))
        iconn = sqlite3.connect(str(src_db))
        assert iconn.execute("SELECT COUNT(*) FROM license_issues").fetchone()[0] == before_rows
        assert iconn.execute("PRAGMA user_version").fetchone()[0] == before_version
        iconn.close()
        print("[7] init_db 幂等校验通过")

        # 8. 安全反证：只恢复库、缺密钥必须拒绝启动
        shutil.move(str(key_dir), str(drill / "keys-hidden"))
        os.environ["LICENSE_SERVICE_DB_PATH"] = str(src_db)
        os.environ["LICENSE_SERVICE_PRIVATE_KEY_PATH"] = str(key_dir / "priv.pem")
        os.environ["LICENSE_SERVICE_PUBLIC_KEY_PATH"] = str(key_dir / "pub.pem")
        os.environ["LICENSE_SERVICE_ADMIN_TOKEN"] = "drill"
        os.environ["LICENSE_SERVICE_MACHINE_CODE_SALT"] = "drill-salt"
        from license_service.config import Config  # noqa: E402
        Config.DATABASE_PATH = str(src_db)
        Config.PRIVATE_KEY_PATH = str(key_dir / "priv.pem")
        Config.PUBLIC_KEY_PATH = str(key_dir / "pub.pem")
        Config.ADMIN_TOKEN = "drill"
        Config.MACHINE_CODE_SALT = "drill-salt"
        from license_service import create_app  # noqa: E402
        try:
            create_app()
            raise SystemExit("FAIL: 缺密钥竟然启动成功，安全行为失效")
        except RuntimeError as exc:
            assert "signing keypair is missing" in str(exc), exc
            print(f"[8] 安全反证通过: 缺密钥拒绝启动（{exc}）")
        shutil.move(str(drill / "keys-hidden"), str(key_dir))

        # 9. 完整恢复后服务可启动
        app = create_app()
        resp = app.test_client().get("/api/v1/health")
        assert resp.status_code == 200 and resp.json["ok"] is True
        print(f"[9] 服务启动校验通过: /health schema_version={resp.json['data'].get('schema_version')}")

        print("\n恢复演练全部通过 ✅")
        return 0
    finally:
        if args.keep:
            print(f"（临时目录保留于 {drill}）")
        else:
            shutil.rmtree(drill, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
