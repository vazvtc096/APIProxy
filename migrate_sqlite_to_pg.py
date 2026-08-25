#!/usr/bin/env python
"""一次性把 SQLite (users.db) 数据泵到 PostgreSQL。

前置（须先完成）：
  1. PostgreSQL 实例已起；DATABASE_URL 指向已建好的空库（如 apiproxy）
  2. 已在 DB_TYPE=postgres 下执行 `alembic upgrade head`，schema 由 smart_init 经
     db.py 抽象层在 PG 上建好
本脚本只搬数据，跳过 alembic_version（由 alembic 自管）。

用法：
  $env:DB_TYPE="postgres"; $env:DATABASE_URL="postgresql://postgres:PW@localhost:5432/apiproxy"
  python -m APIProxy.migrate_sqlite_to_pg
"""
import sqlite3
import sys


def main():
    from APIProxy.configs import DB_TYPE, DATABASE_URL, DB_PATH
    if not (DB_TYPE in ("postgres", "postgresql") and DATABASE_URL):
        print("[!] 需先设 DB_TYPE=postgres + DATABASE_URL")
        sys.exit(2)
    print(f"[+] 源 SQLite: {DB_PATH}")
    print(f"[+] 目标 PG  : {DATABASE_URL}")

    src = sqlite3.connect(DB_PATH)
    src.row_factory = sqlite3.Row
    # 跳过 alembic_version（alembic 自管）与 sqlite 内部表
    tables = [r[0] for r in src.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' AND name<>'alembic_version' ORDER BY name"
    ).fetchall()]

    from APIProxy import db
    total_in = 0
    total_ok = 0
    for t in tables:
        cols = [c[1] for c in src.execute(f'PRAGMA table_info("{t}")').fetchall()]
        rows = src.execute(f'SELECT * FROM "{t}"').fetchall()
        if not rows:
            print(f"  {t:24s} 0 (skip)")
            continue
        collist = ",".join(f'"{c}"' for c in cols)
        ph = ",".join(["?"] * len(cols))
        # INSERT OR IGNORE 经 db._convert_sql 转 ON CONFLICT DO NOTHING，
        # 可吸收 smart_init 在 PG 上已写入的种子行冲突。
        sql = f'INSERT OR IGNORE INTO "{t}" ({collist}) VALUES ({ph})'
        conn = db.get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.executemany(sql, [tuple(r) for r in rows])
                n = cur.rowcount
            n = n if (n and n > 0) else len(rows)
            total_in += len(rows)
            total_ok += n
            print(f"  {t:24s} {n}/{len(rows)}")
        except Exception as e:
            print(f"  {t:24s} FAILED: {e}")
    src.close()
    print(f"[+] 完成：源 {total_in} 行，写入 {total_ok} 行")


if __name__ == "__main__":
    main()
