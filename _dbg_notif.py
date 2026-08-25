"""临时调试：验证 add_notification 是否真正落库并被 unread_count 读到。"""
import os, tempfile, sqlite3

_TD = tempfile.mkdtemp(prefix="dbgnotif_")
os.environ["DB_PATH"] = os.path.join(_TD, "t.db")
os.environ["APIPROXY_OAUTH_JWT_SECRET"] = "x" * 32

from APIProxy.__main__ import create_app, init_database
from APIProxy import notifications, core

init_database()
# 注入一个 admin
import bcrypt
c = core._get_conn()
try:
    cur = c.cursor()
    cur.execute("INSERT INTO users (user_name, user_password, uid, is_admin) VALUES (?,?,?,1)",
                ("dbgadmin", bcrypt.hashpw(b"p", bcrypt.gensalt()).decode(), "deadbeef0001"))
    c.commit()
finally:
    c.close()

app = create_app()  # 触发 init_integrations -> init_notifications

UID = "deadbeef0001"
nid = notifications.add_notification(UID, "标题", "正文")
print("add returned:", nid)

async def chk():
    cnt = await notifications.unread_count(UID)
    items = await notifications.get_notifications(UID)
    print("unread_count:", cnt, "items:", len(items))
    # 直接查物理库
    raw = core._get_conn()
    try:
        r = raw.execute("SELECT id,user_uid,title,is_read FROM notifications").fetchall()
        print("RAW TABLE ROWS:", r)
    finally:
        raw.close()

import asyncio
asyncio.run(chk())
