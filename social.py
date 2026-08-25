"""
社交功能模块
包含帖子系统、好友系统、聊天系统、转账/红包系统
"""
import asyncio
import sqlite3
import uuid
import datetime
from typing import Optional
from quart import request, session, jsonify

# 从主模块导入辅助函数
from .configs import DB_PATH

# ---------- 数据库辅助函数 ----------
def _get_conn():
    """获取数据库连接（SQLite / PostgreSQL，经 db 抽象层统一）"""
    from . import db
    return db.get_conn()

async def async_db_query(sql, args=None):
    """异步执行数据库查询"""
    def _query():
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute(sql, args or ())
            if sql.strip().upper().startswith("SELECT"):
                rows = cur.fetchall()
                return [dict(row) for row in rows]
            else:
                conn.commit()
                return cur.rowcount
    return await asyncio.to_thread(_query)

async def async_db_transaction(operations):
    """异步执行数据库事务
    operations: list of (sql, args) tuples
    """
    def _transaction():
        conn = _get_conn()
        try:
            db.begin_write(conn)
            cur = conn.cursor()
            results = []
            for sql, args in operations:
                cur.execute(sql, args or ())
                if sql.strip().upper().startswith("SELECT"):
                    results.append([dict(row) for row in cur.fetchall()])
                else:
                    results.append(cur.rowcount)
            conn.commit()
            return results
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    return await asyncio.to_thread(_transaction)

# ---------- 辅助函数 ----------
def _generate_post_id() -> str:
    """生成帖子ID"""
    return 'post_' + uuid.uuid4().hex[:16]

def _generate_message_id() -> str:
    """生成消息ID"""
    return 'msg_' + uuid.uuid4().hex[:16]

def _generate_transaction_id() -> str:
    """生成交易ID"""
    return 'tx_' + uuid.uuid4().hex[:16]

async def _get_current_user():
    """获取当前登录用户信息"""
    if 'user' not in session:
        return None
    username = session['user']
    users = await async_db_query(
        "SELECT * FROM users WHERE user_name = ?",
        (username,)
    )
    return users[0] if users else None

async def _is_admin() -> bool:
    """检查当前用户是否是管理员"""
    user = await _get_current_user()
    return bool(user and user.get('is_admin', 0))

async def _require_login():
    """要求登录，返回错误响应或None"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return None

async def _require_admin():
    """要求管理员权限"""
    err = await _require_login()
    if err:
        return err
    if not await _is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403
    return None

async def _get_user_by_uid(uid: str) -> Optional[dict]:
    """通过UID获取用户"""
    users = await async_db_query(
        "SELECT uid, user_name, balence, is_admin, is_banned, created_at FROM users WHERE uid = ?",
        (uid,)
    )
    return users[0] if users else None

async def _are_friends(uid1: str, uid2: str) -> bool:
    """检查两个用户是否是好友"""
    if uid1 == uid2:
        return False
    # 检查双向好友关系
    result = await async_db_query(
        """SELECT id FROM friends 
           WHERE ((user_uid = ? AND friend_uid = ?) OR (user_uid = ? AND friend_uid = ?))
           AND status = 'accepted'
           LIMIT 1""",
        (uid1, uid2, uid2, uid1)
    )
    return len(result) > 0

# ---------- 帖子系统 ----------
async def create_post():
    """创建帖子"""
    err = await _require_login()
    if err:
        return err
    
    data = await request.get_json()
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    tags = data.get('tags', '')
    
    if not title or not content:
        return jsonify({'error': 'Title and content are required'}), 400
    
    if len(title) > 200:
        return jsonify({'error': 'Title too long (max 200 chars)'}), 400
    
    if len(content) > 10000:
        return jsonify({'error': 'Content too long (max 10000 chars)'}), 400
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    post_id = _generate_post_id()
    
    await async_db_query(
        """INSERT INTO posts (post_id, user_uid, user_name, title, content, tags, status)
           VALUES (?, ?, ?, ?, ?, ?, 'pending')""",
        (post_id, user['uid'], user['user_name'], title, content, tags)
    )
    
    return jsonify({
        'message': 'Post created successfully, pending review',
        'post_id': post_id,
        'status': 'pending'
    }), 201

async def list_posts():
    """获取帖子列表（已审核通过的）"""
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(50, max(1, int(request.args.get('per_page', 20))))
    offset = (page - 1) * per_page
    
    # 搜索关键词
    keyword = request.args.get('keyword', '').strip()
    username = request.args.get('username', '').strip()
    
    sql = "SELECT * FROM posts WHERE status = 'approved'"
    count_sql = "SELECT COUNT(*) as cnt FROM posts WHERE status = 'approved'"
    args = []
    count_args = []
    
    if keyword:
        sql += " AND (title LIKE ? OR content LIKE ?)"
        count_sql += " AND (title LIKE ? OR content LIKE ?)"
        args.extend([f'%{keyword}%', f'%{keyword}%'])
        count_args.extend([f'%{keyword}%', f'%{keyword}%'])
    
    if username:
        sql += " AND user_name = ?"
        count_sql += " AND user_name = ?"
        args.append(username)
        count_args.append(username)
    
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([per_page, offset])
    
    posts = await async_db_query(sql, args)
    total_result = await async_db_query(count_sql, count_args)
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'posts': posts,
        'total': total,
        'page': page,
        'per_page': per_page
    })

async def get_post(post_id: str):
    """获取帖子详情"""
    posts = await async_db_query(
        "SELECT * FROM posts WHERE post_id = ?",
        (post_id,)
    )
    
    if not posts:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts[0]
    
    # 未审核通过的帖子只有作者和管理员可以查看
    if post['status'] != 'approved':
        user = await _get_current_user()
        if not user:
            return jsonify({'error': 'Post not found'}), 404
        if user['uid'] != post['user_uid'] and not user.get('is_admin'):
            return jsonify({'error': 'Post not found'}), 404
    
    return jsonify({'post': post})

async def review_post(post_id: str):
    """审核帖子（管理员）"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json()
    action = data.get('action', '')  # approve, reject
    remark = data.get('remark', '')
    
    if action not in ['approve', 'reject']:
        return jsonify({'error': 'Invalid action'}), 400
    
    posts = await async_db_query(
        "SELECT * FROM posts WHERE post_id = ?",
        (post_id,)
    )
    
    if not posts:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts[0]
    
    if post['status'] != 'pending':
        return jsonify({'error': f'Post already {post["status"]}'}), 400
    
    admin = await _get_current_user()
    status = 'approved' if action == 'approve' else 'rejected'
    
    await async_db_query(
        """UPDATE posts SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ?, admin_remark = ?
           WHERE post_id = ?""",
        (status, admin['user_name'] if admin else '', remark, post_id)
    )
    
    return jsonify({
        'message': f'Post {status} successfully',
        'status': status
    })

async def admin_posts():
    """管理员获取待审核帖子列表"""
    err = await _require_admin()
    if err:
        return err
    
    status = request.args.get('status', 'pending')
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(50, max(1, int(request.args.get('per_page', 20))))
    offset = (page - 1) * per_page
    
    if status not in ['pending', 'approved', 'rejected', 'all']:
        status = 'pending'
    
    sql = "SELECT * FROM posts"
    count_sql = "SELECT COUNT(*) as cnt FROM posts"
    args = []
    count_args = []
    
    if status != 'all':
        sql += " WHERE status = ?"
        count_sql += " WHERE status = ?"
        args.append(status)
        count_args.append(status)
    
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([per_page, offset])
    
    posts = await async_db_query(sql, args)
    total_result = await async_db_query(count_sql, count_args)
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'posts': posts,
        'total': total,
        'page': page,
        'per_page': per_page
    })

async def my_posts():
    """获取我的帖子"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(50, max(1, int(request.args.get('per_page', 20))))
    offset = (page - 1) * per_page
    
    posts = await async_db_query(
        "SELECT * FROM posts WHERE user_uid = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (user['uid'], per_page, offset)
    )
    
    total_result = await async_db_query(
        "SELECT COUNT(*) as cnt FROM posts WHERE user_uid = ?",
        (user['uid'],)
    )
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'posts': posts,
        'total': total,
        'page': page,
        'per_page': per_page
    })

# ---------- 帖子收藏 ----------
async def toggle_collection(post_id: str):
    """收藏/取消收藏帖子"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查帖子是否存在且已审核
    posts = await async_db_query(
        "SELECT id, status FROM posts WHERE post_id = ?",
        (post_id,)
    )
    
    if not posts:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts[0]
    post_db_id = post['id']
    
    # 检查是否已收藏
    existing = await async_db_query(
        "SELECT id FROM post_collections WHERE uid = ? AND post_id = ?",
        (user['uid'], post_db_id)
    )
    
    if existing:
        # 取消收藏
        await async_db_query(
            "DELETE FROM post_collections WHERE uid = ? AND post_id = ?",
            (user['uid'], post_db_id)
        )
        return jsonify({'message': 'Post uncollected', 'collected': False})
    else:
        # 添加收藏
        await async_db_query(
            "INSERT INTO post_collections (uid, post_id) VALUES (?, ?)",
            (user['uid'], post_db_id)
        )
        return jsonify({'message': 'Post collected', 'collected': True})

async def my_collections():
    """获取我的收藏列表"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(50, max(1, int(request.args.get('per_page', 20))))
    offset = (page - 1) * per_page
    
    collections = await async_db_query(
        """SELECT p.*, pc.created_at as collected_at 
           FROM post_collections pc
           JOIN posts p ON pc.post_id = p.id
           WHERE pc.uid = ? AND p.status = 'approved'
           ORDER BY pc.created_at DESC
           LIMIT ? OFFSET ?""",
        (user['uid'], per_page, offset)
    )
    
    total_result = await async_db_query(
        """SELECT COUNT(*) as cnt FROM post_collections pc
           JOIN posts p ON pc.post_id = p.id
           WHERE pc.uid = ? AND p.status = 'approved'""",
        (user['uid'],)
    )
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'posts': collections,
        'total': total,
        'page': page,
        'per_page': per_page
    })

# ---------- 好友系统 ----------
async def send_friend_request():
    """发送好友请求"""
    err = await _require_login()
    if err:
        return err
    
    data = await request.get_json()
    friend_uid = data.get('friend_uid', '').strip()
    remark = data.get('remark', '')
    
    if not friend_uid:
        return jsonify({'error': 'Friend UID is required'}), 400
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user['uid'] == friend_uid:
        return jsonify({'error': 'Cannot add yourself as friend'}), 400
    
    # 检查对方是否存在
    friend = await _get_user_by_uid(friend_uid)
    if not friend:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否已经是好友
    if await _are_friends(user['uid'], friend_uid):
        return jsonify({'error': 'Already friends'}), 400
    
    # 检查是否已有待处理的请求
    existing = await async_db_query(
        """SELECT id, status FROM friends 
           WHERE (user_uid = ? AND friend_uid = ?) OR (user_uid = ? AND friend_uid = ?)
           ORDER BY created_at DESC LIMIT 1""",
        (user['uid'], friend_uid, friend_uid, user['uid'])
    )
    
    if existing and existing[0]['status'] == 'pending':
        return jsonify({'error': 'Friend request already pending'}), 400
    
    # 发送好友请求
    await async_db_query(
        """INSERT INTO friends (user_uid, friend_uid, friend_name, status, remark)
           VALUES (?, ?, ?, 'pending', ?)""",
        (user['uid'], friend_uid, friend['user_name'], remark)
    )
    
    return jsonify({'message': 'Friend request sent successfully'})

async def friend_requests():
    """获取好友请求列表（待处理的）"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 收到的好友请求
    received = await async_db_query(
        """SELECT f.id, f.user_uid as from_uid, u.user_name as from_name, f.remark, f.created_at
           FROM friends f
           JOIN users u ON f.user_uid = u.uid
           WHERE f.friend_uid = ? AND f.status = 'pending'
           ORDER BY f.created_at DESC""",
        (user['uid'],)
    )
    
    # 发出的好友请求
    sent = await async_db_query(
        """SELECT f.id, f.friend_uid as to_uid, u.user_name as to_name, f.remark, f.created_at
           FROM friends f
           JOIN users u ON f.friend_uid = u.uid
           WHERE f.user_uid = ? AND f.status = 'pending'
           ORDER BY f.created_at DESC""",
        (user['uid'],)
    )
    
    # 确保名字和 UID 匹配（防止 JOIN 异常或字段混淆）
    for req in received:
        u = await async_db_query("SELECT user_name FROM users WHERE uid = ?", (req['from_uid'],))
        if u:
            req['from_name'] = u[0]['user_name']
    for req in sent:
        if not req.get('to_name'):
            u = await async_db_query("SELECT user_name FROM users WHERE uid = ?", (req['to_uid'],))
            if u:
                req['to_name'] = u[0]['user_name']
    
    return jsonify({
        'received': received,
        'sent': sent
    })

async def accept_friend_request(request_id: int):
    """接受好友请求"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查请求是否存在且是发给我的
    requests = await async_db_query(
        "SELECT * FROM friends WHERE id = ? AND friend_uid = ? AND status = 'pending'",
        (request_id, user['uid'])
    )
    
    if not requests:
        return jsonify({'error': 'Friend request not found'}), 404
    
    req = requests[0]
    
    # 接受请求 - 删除原请求，创建双向好友关系
    def _accept():
        conn = _get_conn()
        try:
            db.begin_write(conn)
            cur = conn.cursor()
            
            # 获取双方用户名
            cur.execute("SELECT user_name FROM users WHERE uid = ?", (req['user_uid'],))
            from_user_row = cur.fetchone()
            from_user_name = from_user_row['user_name'] if from_user_row else ''
            
            cur.execute("SELECT user_name FROM users WHERE uid = ?", (user['uid'],))
            to_user_row = cur.fetchone()
            to_user_name = to_user_row['user_name'] if to_user_row else ''
            
            # 删除原请求记录
            cur.execute("DELETE FROM friends WHERE id = ?", (request_id,))
            
            # 创建双向好友关系
            # 1. 发起者的好友列表里添加接受者
            cur.execute(
                """INSERT INTO friends (user_uid, friend_uid, friend_name, status, accepted_at)
                   VALUES (?, ?, ?, 'accepted', CURRENT_TIMESTAMP)""",
                (req['user_uid'], user['uid'], to_user_name)
            )
            
            # 2. 接受者的好友列表里添加发起者
            cur.execute(
                """INSERT INTO friends (user_uid, friend_uid, friend_name, status, accepted_at)
                   VALUES (?, ?, ?, 'accepted', CURRENT_TIMESTAMP)""",
                (user['uid'], req['user_uid'], from_user_name)
            )
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    await asyncio.to_thread(_accept)
    
    return jsonify({'message': 'Friend request accepted'})

async def reject_friend_request(request_id: int):
    """拒绝好友请求"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查请求是否存在且是发给我的
    requests = await async_db_query(
        "SELECT * FROM friends WHERE id = ? AND friend_uid = ? AND status = 'pending'",
        (request_id, user['uid'])
    )
    
    if not requests:
        return jsonify({'error': 'Friend request not found'}), 404
    
    await async_db_query(
        "UPDATE friends SET status = 'rejected' WHERE id = ?",
        (request_id,)
    )
    
    return jsonify({'message': 'Friend request rejected'})

async def friend_list():
    """获取好友列表"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    friends = await async_db_query(
        """SELECT f.*, u.uid as friend_uid, u.user_name as friend_name,
                  u.last_active_time, u.is_admin, u.is_banned
           FROM friends f
           JOIN users u ON f.friend_uid = u.uid
           WHERE f.user_uid = ? AND f.status = 'accepted'
           ORDER BY u.user_name ASC""",
        (user['uid'],)
    )
    
    # 判断在线状态（5分钟内活跃视为在线）
    now = datetime.datetime.now()
    for friend in friends:
        last_active = friend.get('last_active_time')
        if last_active:
            try:
                last_active_time = datetime.datetime.fromisoformat(str(last_active))
                is_online = (now - last_active_time).total_seconds() < 300  # 5分钟
            except:
                is_online = False
        else:
            is_online = False
        friend['is_online'] = is_online
    
    return jsonify({'friends': friends})

async def delete_friend(friend_uid: str):
    """删除好友（双向删除）"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否是好友
    if not await _are_friends(user['uid'], friend_uid):
        return jsonify({'error': 'Not friends'}), 400
    
    # 双向删除
    await async_db_query(
        """DELETE FROM friends 
           WHERE (user_uid = ? AND friend_uid = ?) OR (user_uid = ? AND friend_uid = ?)""",
        (user['uid'], friend_uid, friend_uid, user['uid'])
    )
    
    return jsonify({'message': 'Friend deleted successfully'})

# ---------- 聊天系统 ----------
async def send_message():
    """发送消息"""
    err = await _require_login()
    if err:
        return err
    
    data = await request.get_json()
    to_uid = data.get('to_uid', '').strip()
    content = data.get('content', '').strip()
    msg_type = data.get('type', 'text')
    
    if not to_uid or not content:
        return jsonify({'error': 'to_uid and content are required'}), 400
    
    if len(content) > 2000:
        return jsonify({'error': 'Message too long (max 2000 chars)'}), 400
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否是好友
    if not await _are_friends(user['uid'], to_uid):
        return jsonify({'error': 'Can only message friends'}), 403
    
    # 检查对方是否存在
    to_user = await _get_user_by_uid(to_uid)
    if not to_user:
        return jsonify({'error': 'Recipient not found'}), 404
    
    message_id = _generate_message_id()
    
    await async_db_query(
        """INSERT INTO chat_messages (message_id, from_uid, from_name, to_uid, to_name, content, type, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'sent', CURRENT_TIMESTAMP)""",
        (message_id, user['uid'], user['user_name'], to_uid, to_user['user_name'], content, msg_type)
    )
    
    return jsonify({
        'message': 'Message sent',
        'message_id': message_id
    }), 201

async def get_messages():
    """获取与某个用户的聊天记录"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    other_uid = request.args.get('uid', '').strip()
    if not other_uid:
        return jsonify({'error': 'uid parameter is required'}), 400
    
    # 检查是否是好友
    if not await _are_friends(user['uid'], other_uid):
        return jsonify({'error': 'Can only view messages with friends'}), 403
    
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(1, int(request.args.get('per_page', 50))))
    offset = (page - 1) * per_page
    
    # 获取双向消息
    messages = await async_db_query(
        """SELECT * FROM chat_messages
           WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?""",
        (user['uid'], other_uid, other_uid, user['uid'], per_page, offset)
    )
    
    # 反转顺序（按时间正序）
    messages.reverse()
    
    # 标记为已读
    await async_db_query(
        """UPDATE chat_messages SET is_read = 1, read_at = CURRENT_TIMESTAMP
           WHERE to_uid = ? AND from_uid = ? AND is_read = 0""",
        (user['uid'], other_uid)
    )
    
    total_result = await async_db_query(
        """SELECT COUNT(*) as cnt FROM chat_messages
           WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)""",
        (user['uid'], other_uid, other_uid, user['uid'])
    )
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'messages': messages,
        'total': total,
        'page': page,
        'per_page': per_page
    })

async def unread_count():
    """获取未读消息总数"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 按发送者分组统计未读消息
    unread = await async_db_query(
        """SELECT from_uid, from_name, COUNT(*) as count
           FROM chat_messages
           WHERE to_uid = ? AND is_read = 0
           GROUP BY from_uid, from_name
           ORDER BY count DESC""",
        (user['uid'],)
    )
    
    total = sum(item['count'] for item in unread)
    
    return jsonify({
        'total': total,
        'by_user': unread
    })

async def conversation_list():
    """获取会话列表"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 获取所有有消息往来的用户及最后一条消息
    conversations = await async_db_query(
        """SELECT 
            CASE 
                WHEN from_uid = ? THEN to_uid 
                ELSE from_uid 
            END as other_uid,
            CASE 
                WHEN from_uid = ? THEN to_name 
                ELSE from_name 
            END as other_name,
            MAX(created_at) as last_message_time,
            (SELECT content FROM chat_messages 
             WHERE (from_uid = ? AND to_uid = other_uid) OR (from_uid = other_uid AND to_uid = ?)
             ORDER BY created_at DESC LIMIT 1) as last_message,
            (SELECT COUNT(*) FROM chat_messages 
             WHERE to_uid = ? AND from_uid = other_uid AND is_read = 0) as unread_count
        FROM chat_messages
        WHERE from_uid = ? OR to_uid = ?
        GROUP BY other_uid, other_name
        ORDER BY last_message_time DESC""",
        (user['uid'], user['uid'], user['uid'], user['uid'], user['uid'], user['uid'], user['uid'])
    )
    
    return jsonify({'conversations': conversations})

# ---------- 转账/红包系统 ----------
async def transfer():
    """转账给好友"""
    err = await _require_login()
    if err:
        return err
    
    data = await request.get_json()
    to_uid = data.get('to_uid', '').strip()
    amount = data.get('amount', 0)
    remark = data.get('remark', '')
    
    if not to_uid or not amount:
        return jsonify({'error': 'to_uid and amount are required'}), 400
    
    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400
    
    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    
    if amount > 1000:
        return jsonify({'error': 'Amount too large (max 1000)'}), 400
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否是好友
    if not await _are_friends(user['uid'], to_uid):
        return jsonify({'error': 'Can only transfer to friends'}), 403
    
    # 检查对方是否存在
    to_user = await _get_user_by_uid(to_uid)
    if not to_user:
        return jsonify({'error': 'Recipient not found'}), 404
    
    # 检查余额
    if user['balence'] < amount:
        return jsonify({'error': 'Insufficient balence'}), 400
    
    transaction_id = _generate_transaction_id()
    
    # 使用事务保证原子性
    def _do_transfer():
        conn = _get_conn()
        try:
            db.begin_write(conn)
            cur = conn.cursor()
            
            # 扣除发送者余额
            cur.execute(
                "UPDATE users SET balence = balence - ? WHERE uid = ?",
                (amount, user['uid'])
            )
            
            # 增加接收者余额
            cur.execute(
                "UPDATE users SET balence = balence + ? WHERE uid = ?",
                (amount, to_uid)
            )
            
            # 记录交易
            cur.execute(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'transfer_out', ?, ?, ?, ?)""",
                (transaction_id + '_out', user['uid'], user['user_name'], -amount, user['balence'] - amount, to_uid, remark)
            )
            
            cur.execute(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'transfer_in', ?, ?, ?, ?)""",
                (transaction_id + '_in', to_uid, to_user['user_name'], amount, to_user['balence'] + amount, user['uid'], remark)
            )
            
            # 发送系统消息
            message_id = _generate_message_id()
            cur.execute(
                """INSERT INTO chat_messages (message_id, from_uid, from_name, to_uid, to_name, content, type, amount, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'transfer', ?, 'sent', CURRENT_TIMESTAMP)""",
                (message_id, user['uid'], user['user_name'], to_uid, to_user['user_name'], 
                 f'转账 ¥{amount:.2f}', amount)
            )
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    await asyncio.to_thread(_do_transfer)
    
    return jsonify({
        'message': 'Transfer successful',
        'transaction_id': transaction_id,
        'amount': amount
    })

async def send_redpacket():
    """发红包给好友"""
    err = await _require_login()
    if err:
        return err
    
    data = await request.get_json()
    to_uid = data.get('to_uid', '').strip()
    amount = data.get('amount', 0)
    remark = data.get('remark', '恭喜发财，大吉大利')
    
    if not to_uid or not amount:
        return jsonify({'error': 'to_uid and amount are required'}), 400
    
    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400
    
    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    
    if amount > 200:
        return jsonify({'error': 'Red packet amount too large (max 200)'}), 400
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否是好友
    if not await _are_friends(user['uid'], to_uid):
        return jsonify({'error': 'Can only send red packets to friends'}), 403
    
    # 检查对方是否存在
    to_user = await _get_user_by_uid(to_uid)
    if not to_user:
        return jsonify({'error': 'Recipient not found'}), 404
    
    # 检查余额
    if user['balence'] < amount:
        return jsonify({'error': 'Insufficient balence'}), 400
    
    transaction_id = _generate_transaction_id()
    
    # 使用事务保证原子性
    def _do_redpacket():
        conn = _get_conn()
        try:
            db.begin_write(conn)
            cur = conn.cursor()
            
            # 扣除发送者余额
            cur.execute(
                "UPDATE users SET balence = balence - ? WHERE uid = ?",
                (amount, user['uid'])
            )
            
            # 增加接收者余额
            cur.execute(
                "UPDATE users SET balence = balence + ? WHERE uid = ?",
                (amount, to_uid)
            )
            
            # 记录交易
            cur.execute(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'redpacket_send', ?, ?, ?, ?)""",
                (transaction_id + '_send', user['uid'], user['user_name'], -amount, user['balence'] - amount, to_uid, remark)
            )
            
            cur.execute(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'redpacket_recv', ?, ?, ?, ?)""",
                (transaction_id + '_recv', to_uid, to_user['user_name'], amount, to_user['balence'] + amount, user['uid'], remark)
            )
            
            # 发送红包消息
            message_id = _generate_message_id()
            cur.execute(
                """INSERT INTO chat_messages (message_id, from_uid, from_name, to_uid, to_name, content, type, amount, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'redpacket', ?, 'sent')""",
                (message_id, user['uid'], user['user_name'], to_uid, to_user['user_name'], 
                 f'{remark} ¥{amount:.2f}', amount)
            )
            
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    await asyncio.to_thread(_do_redpacket)
    
    return jsonify({
        'message': 'Red packet sent successfully',
        'transaction_id': transaction_id,
        'amount': amount
    })

async def transaction_history():
    """获取交易记录"""
    err = await _require_login()
    if err:
        return err
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(1, int(request.args.get('per_page', 20))))
    offset = (page - 1) * per_page
    
    tx_type = request.args.get('type', '')  # transfer, redpacket, all
    
    sql = "SELECT * FROM balence_transactions WHERE user_uid = ?"
    count_sql = "SELECT COUNT(*) as cnt FROM balence_transactions WHERE user_uid = ?"
    args = [user['uid']]
    count_args = [user['uid']]
    
    if tx_type and tx_type != 'all':
        if tx_type == 'transfer':
            sql += " AND (type = 'transfer_out' OR type = 'transfer_in')"
            count_sql += " AND (type = 'transfer_out' OR type = 'transfer_in')"
        elif tx_type == 'redpacket':
            sql += " AND (type = 'redpacket_send' OR type = 'redpacket_recv')"
            count_sql += " AND (type = 'redpacket_send' OR type = 'redpacket_recv')"
    
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([per_page, offset])
    
    transactions = await async_db_query(sql, args)
    total_result = await async_db_query(count_sql, count_args)
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'transactions': transactions,
        'total': total,
        'page': page,
        'per_page': per_page
    })

# ---------- 注册路由 ----------
def register_social_routes(app):
    """注册社交功能路由"""
    
    # 帖子系统
    app.add_url_rule('/api/posts', 'list_posts', list_posts, methods=['GET'])
    app.add_url_rule('/api/posts', 'create_post', create_post, methods=['POST'])
    app.add_url_rule('/api/posts/mine', 'my_posts', my_posts, methods=['GET'])
    app.add_url_rule('/api/posts/<post_id>', 'get_post', get_post, methods=['GET'])
    app.add_url_rule('/api/posts/<post_id>/review', 'review_post', review_post, methods=['POST'])
    app.add_url_rule('/api/admin/posts', 'admin_posts', admin_posts, methods=['GET'])
    
    # 帖子收藏
    app.add_url_rule('/api/posts/<post_id>/collection', 'toggle_collection', toggle_collection, methods=['POST'])
    app.add_url_rule('/api/posts/collections/mine', 'my_collections', my_collections, methods=['GET'])
    
    # 好友系统
    app.add_url_rule('/api/friends/request', 'send_friend_request', send_friend_request, methods=['POST'])
    app.add_url_rule('/api/friends/requests', 'friend_requests', friend_requests, methods=['GET'])
    app.add_url_rule('/api/friends/requests/<int:request_id>/accept', 'accept_friend_request', accept_friend_request, methods=['POST'])
    app.add_url_rule('/api/friends/requests/<int:request_id>/reject', 'reject_friend_request', reject_friend_request, methods=['POST'])
    app.add_url_rule('/api/friends', 'friend_list', friend_list, methods=['GET'])
    app.add_url_rule('/api/friends/<friend_uid>', 'delete_friend', delete_friend, methods=['DELETE'])
    
    # 聊天系统
    app.add_url_rule('/api/chat/send', 'send_message', send_message, methods=['POST'])
    app.add_url_rule('/api/chat/messages', 'get_messages', get_messages, methods=['GET'])
    app.add_url_rule('/api/chat/unread', 'unread_count', unread_count, methods=['GET'])
    app.add_url_rule('/api/chat/conversations', 'conversation_list', conversation_list, methods=['GET'])
    
    # 转账/红包系统
    app.add_url_rule('/api/transfer', 'transfer', transfer, methods=['POST'])
    app.add_url_rule('/api/redpacket', 'send_redpacket', send_redpacket, methods=['POST'])
    app.add_url_rule('/api/transactions', 'transaction_history', transaction_history, methods=['GET'])
