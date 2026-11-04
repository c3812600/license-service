#!/usr/bin/env python3
"""SQLite 在线热备（VACUUM INTO，含 WAL，一致性快照，不会得到损坏库）。
用法: backup_db.py [源db] [备份目录]
默认备份 /www/wwwroot/license-service/data/license-service.db -> data/backups/
"""
import datetime
import os
import sqlite3
import sys

DEFAULT_SRC = "/www/wwwroot/license-service/data/license-service.db"
DEFAULT_OUT = "/www/wwwroot/license-service/data/backups"


def backup(src=DEFAULT_SRC, out_dir=DEFAULT_OUT):
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(out_dir, "license-service_%s.db" % ts)
    conn = sqlite3.connect(src)
    try:
        conn.execute("VACUUM INTO ?", (out,))
    finally:
        conn.close()
    return out


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    out_dir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    print("备份:", backup(src, out_dir))
