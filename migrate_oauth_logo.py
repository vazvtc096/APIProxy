"""
OAuth 客户端 logo 字段迁移脚本
给 oauth_clients 表增加 logo_base64 字段，用于存储应用 Logo（Base64 编码）。

使用方法：
    python migrate_oauth_logo.py

也可以在 smart_init.py / init_db.py 中自动执行（推荐加到初始化流程末尾）。
"""
import sqlite3
import os
import sys

# 数据库文件路径（与项目保持一致）
DB_PATH = os.environ.get('APIPROXY_DB', 'apiproxy.db')


def migrate(db_path: str = DB_PATH) -> bool:
    """执行迁移：给 oauth_clients 表增加 logo_base64 字段。"""
    if not os.path.exists(db_path):
        print(f"[ERROR] 数据库文件不存在: {db_path}")
        return False

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    try:
        # 检查表是否存在
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_clients'")
        if not cur.fetchone():
            print("[WARN] oauth_clients 表不存在，跳过迁移（首次初始化会自动创建含 logo_base64 的表）")
            conn.close()
            return True

        # 检查 logo_base64 字段是否已存在
        cur.execute("PRAGMA table_info(oauth_clients)")
        columns = [row[1] for row in cur.fetchall()]

        if 'logo_base64' in columns:
            print("[OK] logo_base64 字段已存在，无需迁移")
            conn.close()
            return True

        # 执行 ALTER TABLE 增加字段
        cur.execute("ALTER TABLE oauth_clients ADD COLUMN logo_base64 TEXT DEFAULT ''")
        conn.commit()
        print("[OK] 已为 oauth_clients 表增加 logo_base64 字段")

        # 验证
        cur.execute("PRAGMA table_info(oauth_clients)")
        columns = [row[1] for row in cur.fetchall()]
        if 'logo_base64' in columns:
            print("[OK] 验证通过：logo_base64 字段已存在")
        else:
            print("[ERROR] 验证失败：logo_base64 字段未找到")
            conn.close()
            return False

    except Exception as e:
        print(f"[ERROR] 迁移失败: {e}")
        conn.rollback()
        conn.close()
        return False

    conn.close()
    return True


if __name__ == '__main__':
    db = sys.argv[1] if len(sys.argv) > 1 else DB_PATH
    success = migrate(db)
    sys.exit(0 if success else 1)
