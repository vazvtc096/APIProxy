"""
社交功能数据库迁移脚本
基于现有表结构，添加缺失字段和新表
"""
import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'users.db')

def column_exists(cur, table, column):
    """检查列是否存在"""
    cur.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cur.fetchall()]
    return column in columns

def migrate_social():
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    print("正在迁移社交功能数据库...")
    
    # 1. 修改 posts 表，添加 tags 字段
    if not column_exists(cur, 'posts', 'tags'):
        cur.execute("ALTER TABLE posts ADD COLUMN tags TEXT DEFAULT ''")
        print("  [OK] posts 表添加 tags 字段")
    else:
        print("  [OK] posts 表 tags 字段已存在")
    
    # 添加 reviewed_at 和 reviewed_by 字段（用于审核）
    if not column_exists(cur, 'posts', 'reviewed_at'):
        cur.execute("ALTER TABLE posts ADD COLUMN reviewed_at TIMESTAMP")
        print("  [OK] posts 表添加 reviewed_at 字段")
    
    if not column_exists(cur, 'posts', 'reviewed_by'):
        cur.execute("ALTER TABLE posts ADD COLUMN reviewed_by TEXT")
        print("  [OK] posts 表添加 reviewed_by 字段")
    
    # 2. post_collections 表（帖子收藏）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS post_collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL,
            post_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(uid, post_id)
        )
    """)
    print("  [OK] post_collections 表")
    
    cur.execute("CREATE INDEX IF NOT EXISTS idx_collections_uid ON post_collections(uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_collections_post ON post_collections(post_id)")
    
    # 3. friends 表已存在，检查并添加必要索引
    cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_friend ON friends(friend_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_status ON friends(status)")
    print("  [OK] friends 表索引")
    
    # 4. chat_messages 表已存在，检查并添加必要索引
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_from ON chat_messages(from_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_to ON chat_messages(to_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_created ON chat_messages(created_at)")
    print("  [OK] chat_messages 表索引")
    
    # 5. balence_transactions 表已存在，检查并添加必要索引
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_user ON balence_transactions(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_created ON balence_transactions(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_type ON balence_transactions(type)")
    print("  [OK] balence_transactions 表索引")
    
    # 6. 检查并添加用户在线状态字段（用于好友在线显示）
    if not column_exists(cur, 'users', 'last_active_time'):
        cur.execute("ALTER TABLE users ADD COLUMN last_active_time TIMESTAMP")
        print("  [OK] users 表添加 last_active_time 字段")
    else:
        print("  [OK] users 表 last_active_time 字段已存在")
    
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 40)
    print("社交功能数据库迁移完成！")
    print("=" * 40)

if __name__ == '__main__':
    migrate_social()
