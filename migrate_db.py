import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'users.db')

def migrate():
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # 检查 email 列是否存在
    cur.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cur.fetchall()]
    
    if 'email' not in columns:
        print("添加 email 字段...")
        cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        print("完成！")
    else:
        print("email 字段已存在，无需迁移")
    
    # 检查其他字段
    if 'uid' not in columns:
        print("添加 uid 字段...")
        cur.execute("ALTER TABLE users ADD COLUMN uid TEXT")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_uid ON users(uid)")
        # 给现有用户生成 uid
        import uuid
        cur.execute("SELECT id, user_name FROM users WHERE uid IS NULL OR uid = ''")
        for row in cur.fetchall():
            uid = uuid.uuid4().hex[:12]
            cur.execute("UPDATE users SET uid = ? WHERE id = ?", (uid, row[0]))
            print(f"  用户 {row[1]} -> {uid}")
        print("uid 字段添加完成！")
    
    if 'is_admin' not in columns:
        print("添加 is_admin 字段...")
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        print("完成！")
    
    if 'is_banned' not in columns:
        print("添加封禁相关字段...")
        cur.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0")
        cur.execute("ALTER TABLE users ADD COLUMN ban_reason TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN ban_expire_at TIMESTAMP")
        print("完成！")
    
    conn.commit()
    conn.close()
    print("\n数据库迁移完成！")

if __name__ == '__main__':
    migrate()
