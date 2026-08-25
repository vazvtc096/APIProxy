import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'users.db')

def check_users():
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    cur.execute("SELECT id, user_name, user_password, balence, uid, email FROM users")
    users = cur.fetchall()
    
    print(f"共有 {len(users)} 个用户:\n")
    for u in users:
        print(f"ID: {u[0]}")
        print(f"用户名: {u[1]}")
        print(f"密码哈希: {u[2][:30]}...")
        print(f"余额: {u[3]}")
        print(f"UID: {u[4]}")
        print(f"邮箱: {u[5]}")
        print("-" * 40)
    
    conn.close()

if __name__ == '__main__':
    check_users()
