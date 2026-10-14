"""社交路由：帖子/好友/聊天/转账"""
import asyncio
import json
import logging

from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
from ..app import app
from ..core import *
from .. import social, oauth, upstreams, pricing
from .. import hooks as _hooks
from .. import announcements as _ann
from .. import notifications as _ntf
from .. import system_users as _su
from ..apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from ..configs import BASEURL, APIKEY, DEBUG_CONSOLE_ENABLED, DEBUG_CONSOLE_SECRET, SSL_ENABLED, SESSION_SECRET, OAUTH_JWT_SECRET, SMTP_CONFIGURED
from .. import configs
from .. import db
from ..constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from ..cloudflare import get_client_ip as _cf_get_client_ip
from .. import waf as _waf

social_bp = Blueprint('social', __name__)

@social_bp.route('/api/posts', methods=['GET'])
async def list_posts():
    """获取帖子列表（已审核通过的）"""
    _oerr = await _oauth_ensure_user(['posts:read'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    # 获取查询参数
    page = int(request.args.get('page', 1))
    page_size = min(int(request.args.get('page_size', 20)), 100)
    offset = (page - 1) * page_size
    
    # 获取已审核通过的帖子
    posts = await async_db_query(
        """SELECT p.*, 
           (SELECT COUNT(*) FROM post_favorites pf WHERE pf.post_id = p.post_id) as favorite_count
           FROM posts p 
           WHERE p.status = 'approved' 
           ORDER BY p.created_at DESC 
           LIMIT ? OFFSET ?""",
        (page_size, offset)
    )
    
    # 获取总数
    total_result = await async_db_query(
        "SELECT COUNT(*) as cnt FROM posts WHERE status = 'approved'"
    )
    total = total_result[0]['cnt'] if total_result else 0
    
    # 检查当前用户是否收藏了这些帖子，以及是否是作者
    current_user = await _get_current_user()
    if current_user:
        for post in posts:
            fav = await async_db_query(
                "SELECT id FROM post_favorites WHERE user_uid = ? AND post_id = ?",
                (current_user['uid'], post['post_id'])
            )
            post['is_favorited'] = len(fav) > 0
            post['is_owner'] = post['user_uid'] == current_user['uid']
    else:
        for post in posts:
            post['is_favorited'] = False
            post['is_owner'] = False
    
    return jsonify({
        'posts': posts,
        'total': total,
        'page': page,
        'page_size': page_size
    })


@social_bp.route('/api/posts/my', methods=['GET'])
async def my_posts():
    """获取我的帖子"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 获取查询参数
    page = int(request.args.get('page', 1))
    page_size = min(int(request.args.get('page_size', 20)), 100)
    status = request.args.get('status', '')
    offset = (page - 1) * page_size
    
    # 构建查询
    sql = "SELECT * FROM posts WHERE user_uid = ?"
    args = [user['uid']]
    
    if status and status in ['pending', 'approved', 'rejected']:
        sql += " AND status = ?"
        args.append(status)
    
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([page_size, offset])
    
    posts = await async_db_query(sql, args)
    
    # 获取总数
    count_sql = "SELECT COUNT(*) as cnt FROM posts WHERE user_uid = ?"
    count_args = [user['uid']]
    if status and status in ['pending', 'approved', 'rejected']:
        count_sql += " AND status = ?"
        count_args.append(status)
    
    total_result = await async_db_query(count_sql, count_args)
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'posts': posts,
        'total': total,
        'page': page,
        'page_size': page_size
    })


@social_bp.route('/api/posts/<post_id>', methods=['GET'])
async def get_post(post_id):
    """获取帖子详情"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    posts = await async_db_query(
        "SELECT * FROM posts WHERE post_id = ?",
        (post_id,)
    )
    
    if not posts:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts[0]
    
    # 只有已审核的帖子或作者本人可以查看
    current_user = await _get_current_user()
    if post['status'] != 'approved' and (not current_user or post['user_uid'] != current_user['uid']):
        # 管理员也可以查看
        if not current_user or not current_user.get('is_admin'):
            return jsonify({'error': 'Post not found'}), 404
    
    # 检查是否收藏
    if current_user:
        fav = await async_db_query(
            "SELECT id FROM post_favorites WHERE user_uid = ? AND post_id = ?",
            (current_user['uid'], post_id)
        )
        post['is_favorited'] = len(fav) > 0
    else:
        post['is_favorited'] = False
    
    # 获取收藏数
    fav_count = await async_db_query(
        "SELECT COUNT(*) as cnt FROM post_favorites WHERE post_id = ?",
        (post_id,)
    )
    post['favorite_count'] = fav_count[0]['cnt'] if fav_count else 0
    
    return jsonify({'post': post})


@social_bp.route('/api/posts', methods=['POST'])
async def create_post():
    """发布新帖子（待审核）"""
    # 限流检查
    allowed, remaining = _check_rate_limit('post')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429
    
    _oerr = await _oauth_ensure_user(['posts:write'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否被封禁
    is_banned, ban_msg = await _is_user_banned(user)
    if is_banned:
        return jsonify({'error': f'Account banned: {ban_msg}'}), 403
    
    data = await request.get_json() or {}
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()

    if not title:
        return jsonify({'error': 'Title required'}), 400
    if not content:
        return jsonify({'error': 'Content required'}), 400

    # 输入净化：防御存储型 XSS（移除 script/iframe/on* 等）
    title = _sanitize_user_content(title)
    content = _sanitize_user_content(content)
    
    # 长度限制
    if len(title) > 200:
        return jsonify({'error': 'Title too long (max 200 chars)'}), 400
    if len(content) > 10000:
        return jsonify({'error': 'Content too long (max 10000 chars)'}), 400
    
    post_id = _generate_post_id()
    
    await async_db_query(
        """INSERT INTO posts 
           (post_id, user_uid, user_name, title, content, status)
           VALUES (?, ?, ?, ?, ?, 'pending')""",
        (post_id, user['uid'], user['user_name'], title, content)
    )

    # 触发钩子事件：发布新帖子
    await fire_event('POST_CREATE', trigger_user=user['uid'], post_id=post_id, content=content)

    logging.info(f"Post created: {post_id} by user {user['user_name']}")
    
    return jsonify({
        'message': 'Post submitted for review',
        'post_id': post_id,
        'status': 'pending'
    }), 201


@social_bp.route('/api/posts/<post_id>/favorite', methods=['POST'])
async def toggle_favorite(post_id):
    """收藏/取消收藏帖子"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查帖子是否存在且已审核
    posts = await async_db_query(
        "SELECT * FROM posts WHERE post_id = ?",
        (post_id,)
    )
    if not posts:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts[0]
    if post['status'] != 'approved':
        return jsonify({'error': 'Post not found'}), 404
    
    # 检查是否已收藏
    existing = await async_db_query(
        "SELECT id FROM post_favorites WHERE user_uid = ? AND post_id = ?",
        (user['uid'], post_id)
    )
    
    if existing:
        # 取消收藏
        await async_db_query(
            "DELETE FROM post_favorites WHERE user_uid = ? AND post_id = ?",
            (user['uid'], post_id)
        )
        is_favorited = False
        message = 'Removed from favorites'
    else:
        # 添加收藏
        await async_db_query(
            "INSERT INTO post_favorites (user_uid, post_id) VALUES (?, ?)",
            (user['uid'], post_id)
        )
        is_favorited = True
        message = 'Added to favorites'
    
    return jsonify({
        'message': message,
        'is_favorited': is_favorited
    })


@social_bp.route('/api/posts/<post_id>', methods=['DELETE'])
async def delete_post(post_id):
    """删除帖子（作者本人或管理员）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 查询帖子
    post = await async_db_query(
        "SELECT * FROM posts WHERE post_id = ?",
        (post_id,),
        fetch_one=True
    )
    
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    # 权限检查：只能删除自己的帖子，管理员可以删除任何帖子
    is_admin = user.get('is_admin', 0)
    if post['user_uid'] != user['uid'] and not is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    # 删除帖子
    await async_db_query(
        "DELETE FROM posts WHERE post_id = ?",
        (post_id,)
    )
    
    # 删除相关的收藏记录
    await async_db_query(
        "DELETE FROM post_favorites WHERE post_id = ?",
        (post_id,)
    )
    
    logging.info(f"Post deleted: {post_id} by user {user['user_name']}")
    
    return jsonify({'message': 'Post deleted successfully'}), 200



@social_bp.route('/api/posts/favorites', methods=['GET'])
async def my_favorites():
    """获取我的收藏列表"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    page = int(request.args.get('page', 1))
    page_size = min(int(request.args.get('page_size', 20)), 100)
    offset = (page - 1) * page_size
    
    # 获取收藏的帖子
    posts = await async_db_query(
        """SELECT p.*, pf.created_at as favorited_at
           FROM post_favorites pf
           JOIN posts p ON pf.post_id = p.post_id
           WHERE pf.user_uid = ? AND p.status = 'approved'
           ORDER BY pf.created_at DESC
           LIMIT ? OFFSET ?""",
        (user['uid'], page_size, offset)
    )
    
    # 获取总数
    total_result = await async_db_query(
        """SELECT COUNT(*) as cnt FROM post_favorites pf
           JOIN posts p ON pf.post_id = p.post_id
           WHERE pf.user_uid = ? AND p.status = 'approved'""",
        (user['uid'],)
    )
    total = total_result[0]['cnt'] if total_result else 0
    
    # 标记为已收藏
    for post in posts:
        post['is_favorited'] = True
    
    return jsonify({
        'posts': posts,
        'total': total,
        'page': page,
        'page_size': page_size
    })

# ---------- 管理员帖子审核 API ----------


@social_bp.route('/api/users/search', methods=['GET'])
async def search_users():
    """搜索用户"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    keyword = request.args.get('q', '').strip()
    
    if not keyword or len(keyword) < 2:
        return jsonify({'error': 'Search keyword must be at least 2 characters'}), 400
    
    # 搜索用户（用户名或UID）
    users = await async_db_query(
        """SELECT uid, user_name, created_at, is_admin 
           FROM users 
           WHERE user_name LIKE ? OR uid LIKE ?
           LIMIT 20""",
        (f'%{keyword}%', f'%{keyword}%')
    )
    
    # 移除当前用户与系统虚拟用户（UID 池 0~15 不可搜索、不可加好友）
    current_user = await _get_current_user()
    if current_user:
        users = [u for u in users if u['uid'] != current_user['uid']]
    users = [u for u in users if not _su.is_system_uid(u['uid'])]

    return jsonify({'users': users})


@social_bp.route('/api/friends', methods=['GET'])
async def list_friends():
    """获取好友列表"""
    _oerr = await _oauth_ensure_user(['friends:read'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 获取已接受的好友（双向查询）
    friends = await async_db_query(
        """SELECT f.friend_uid as uid, f.friend_name as user_name, f.remark, f.accepted_at
           FROM friends f
           WHERE f.user_uid = ? AND f.status = 'accepted'
           ORDER BY f.friend_name""",
        (user['uid'],)
    )
    
    # 获取每个好友的最后一条消息
    for friend in friends:
        last_msg = await async_db_query(
            """SELECT * FROM chat_messages 
               WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)
               ORDER BY created_at DESC LIMIT 1""",
            (user['uid'], friend['uid'], friend['uid'], user['uid'])
        )
        friend['last_message'] = last_msg[0] if last_msg else None
        
        # 获取未读消息数
        unread = await async_db_query(
            """SELECT COUNT(*) as cnt FROM chat_messages 
               WHERE from_uid = ? AND to_uid = ? AND status = 'sent'""",
            (friend['uid'], user['uid'])
        )
        friend['unread_count'] = unread[0]['cnt'] if unread else 0

    # 注入与系统虚拟用户（UID 池 0~15）的会话：有消息往来才出现，免好友关系
    try:
        sys_uids = list(_su.SYSTEM_USERS.keys())
        ph = ','.join('?' * len(sys_uids))
        sys_rows = await async_db_query(
            f"""SELECT from_uid, COUNT(*) as cnt FROM chat_messages
                WHERE to_uid = ? AND from_uid IN ({ph}) AND COALESCE(is_read, 0) = 0
                GROUP BY from_uid""",
            tuple([user['uid']] + sys_uids)
        ) or []
        sys_unread = {r['from_uid']: r['cnt'] for r in sys_rows}
        for s_uid in sys_uids:
            s_last = await async_db_query(
                """SELECT * FROM chat_messages
                   WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)
                   ORDER BY created_at DESC LIMIT 1""",
                (user['uid'], s_uid, s_uid, user['uid'])
            )
            if not s_last and not sys_unread.get(s_uid):
                continue  # 无消息往来不出现在列表
            _uname, display = _su.get_system_user(s_uid)
            friends.append({
                'uid': s_uid,
                'user_name': display,
                'remark': _su.SYSTEM_USERS[s_uid][2],
                'accepted_at': None,
                'last_message': s_last[0] if s_last else None,
                'unread_count': sys_unread.get(s_uid, 0),
                'is_system': True,
                'is_protected': True,
            })
    except Exception as e:
        logging.warning(f'inject system conversations to /api/friends failed: {e}')

    return jsonify({'friends': friends})


@social_bp.route('/api/friends/requests', methods=['GET'])
async def list_friend_requests():
    """获取好友请求列表"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 收到的好友请求
    received = await async_db_query(
        """SELECT f.id, f.user_uid as from_uid, u.user_name as from_name, f.created_at
           FROM friends f
           JOIN users u ON f.user_uid = u.uid
           WHERE f.friend_uid = ? AND f.status = 'pending'
           ORDER BY f.created_at DESC""",
        (user['uid'],)
    )
    
    # 发出的好友请求
    sent = await async_db_query(
        """SELECT f.id, f.friend_uid as to_uid, u.user_name as to_name, f.created_at
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
        u = await async_db_query("SELECT user_name FROM users WHERE uid = ?", (req['to_uid'],))
        if u:
            req['to_name'] = u[0]['user_name']
    
    return jsonify({
        'received': received,
        'sent': sent
    })


@social_bp.route('/api/friends/request', methods=['POST'])
async def send_friend_request():
    """发送好友请求"""
    # 限流检查
    allowed, remaining = _check_rate_limit('friend')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429
    
    _oerr = await _oauth_ensure_user(['friends:write'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = await request.get_json() or {}
    friend_uid = (data.get('user_uid') or data.get('friend_uid') or '').strip()
    remark = data.get('remark', '').strip()
    remark = _sanitize_user_content(remark)
    
    if not friend_uid:
        return jsonify({'error': 'User UID required'}), 400
    
    # 不能加自己为好友
    if friend_uid == user['uid']:
        return jsonify({'error': 'Cannot add yourself as friend'}), 400

    # 系统虚拟用户不可加好友（聊天入口由会话列表自动注入，无需好友关系）
    if _su.is_system_uid(friend_uid):
        return jsonify({'error': '系统用户不可添加为好友'}), 400
    
    # 检查对方用户是否存在
    target_users = await async_db_query(
        "SELECT uid, user_name FROM users WHERE uid = ?",
        (friend_uid,)
    )
    if not target_users:
        return jsonify({'error': 'User not found'}), 404
    
    target_user = target_users[0]
    
    # 检查是否已经是好友或已有请求
    existing = await async_db_query(
        """SELECT * FROM friends 
           WHERE (user_uid = ? AND friend_uid = ?) OR (user_uid = ? AND friend_uid = ?)""",
        (user['uid'], friend_uid, friend_uid, user['uid'])
    )
    
    if existing:
        rel = existing[0]
        if rel['status'] == 'accepted':
            return jsonify({'error': 'Already friends'}), 400
        elif rel['status'] == 'pending':
            return jsonify({'error': 'Friend request already pending'}), 400
        elif rel['status'] == 'rejected':
            # 如果之前被拒绝了，可以重新发送
            pass
    
    # 删除旧的关系记录（如果有）
    await async_db_query(
        "DELETE FROM friends WHERE (user_uid = ? AND friend_uid = ?) OR (user_uid = ? AND friend_uid = ?)",
        (user['uid'], friend_uid, friend_uid, user['uid'])
    )
    
    # 创建好友请求
    await async_db_query(
        """INSERT INTO friends (user_uid, friend_uid, friend_name, status, remark)
           VALUES (?, ?, ?, 'pending', ?)""",
        (user['uid'], friend_uid, target_user['user_name'], remark)
    )
    
    logging.info(f"Friend request sent: {user['user_name']} -> {target_user['user_name']}")
    
    return jsonify({'message': 'Friend request sent'}), 201


@social_bp.route('/api/friends/requests/<int:request_id>/accept', methods=['POST'])
async def accept_friend_request(request_id):
    """接受好友请求"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查请求是否存在且是发给当前用户的
    requests = await async_db_query(
        "SELECT * FROM friends WHERE id = ? AND friend_uid = ? AND status = 'pending'",
        (request_id, user['uid'])
    )
    
    if not requests:
        return jsonify({'error': 'Friend request not found'}), 404
    
    req = requests[0]
    
    # 查询发起者的用户名
    from_user = await async_db_query(
        "SELECT user_name FROM users WHERE uid = ?",
        (req['user_uid'],)
    )
    from_user_name = from_user[0]['user_name'] if from_user else '未知用户'
    
    # 更新请求状态为已接受
    await async_db_query(
        "UPDATE friends SET status = 'accepted', accepted_at = CURRENT_TIMESTAMP WHERE id = ?",
        (request_id,)
    )
    
    # 创建反向关系
    await async_db_query(
        """INSERT INTO friends (user_uid, friend_uid, friend_name, status, accepted_at)
           VALUES (?, ?, ?, 'accepted', CURRENT_TIMESTAMP)""",
        (user['uid'], req['user_uid'], from_user_name)
    )
    
    # 发送系统消息
    msg_id = _generate_message_id()
    await async_db_query(
        """INSERT INTO chat_messages 
           (message_id, from_uid, from_name, to_uid, to_name, content, type, status)
           VALUES (?, ?, ?, ?, ?, ?, 'system', 'sent')""",
        (msg_id, 'system', '系统', req['user_uid'], from_user_name, 
         f'{user["user_name"]} 接受了你的好友请求')
    )

    # 触发钩子事件：好友请求被接受
    await fire_event('FRIEND_ACCEPTED', trigger_user=user['uid'], target_user=req['user_uid'])

    logging.info(f"Friend request accepted: {from_user_name} <-> {user['user_name']}")
    
    return jsonify({'message': 'Friend request accepted'})


@social_bp.route('/api/friends/requests/<int:request_id>/reject', methods=['POST'])
async def reject_friend_request(request_id):
    """拒绝好友请求"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查请求是否存在且是发给当前用户的
    requests = await async_db_query(
        "SELECT * FROM friends WHERE id = ? AND friend_uid = ? AND status = 'pending'",
        (request_id, user['uid'])
    )
    
    if not requests:
        return jsonify({'error': 'Friend request not found'}), 404
    
    req = requests[0]
    
    # 更新状态为已拒绝
    await async_db_query(
        "UPDATE friends SET status = 'rejected' WHERE id = ?",
        (request_id,)
    )
    
    logging.info(f"Friend request rejected: {req['user_uid']} -> {user['user_name']}")
    
    return jsonify({'message': 'Friend request rejected'})


@social_bp.route('/api/friends/<friend_uid>', methods=['DELETE'])
async def delete_friend(friend_uid):
    """删除好友"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否是好友
    friends = await async_db_query(
        "SELECT * FROM friends WHERE user_uid = ? AND friend_uid = ? AND status = 'accepted'",
        (user['uid'], friend_uid)
    )
    
    if not friends:
        return jsonify({'error': 'Friend not found'}), 404
    
    friend = friends[0]

    # 受保护好友（内置 admin 通知渠道）不允许删除
    if friend.get('is_protected'):
        return jsonify({'error': '该好友为系统通知渠道，无法删除'}), 403
    target = await async_db_query(
        "SELECT user_name, is_admin FROM users WHERE uid = ?", (friend_uid,), fetch_one=True
    )
    if target and target.get('user_name') == 'admin':
        return jsonify({'error': '该好友为系统通知渠道，无法删除'}), 403
    
    # 删除双向好友关系
    await async_db_query(
        "DELETE FROM friends WHERE (user_uid = ? AND friend_uid = ?) OR (user_uid = ? AND friend_uid = ?)",
        (user['uid'], friend_uid, friend_uid, user['uid'])
    )
    
    logging.info(f"Friend deleted: {user['user_name']} <-> {friend['friend_name']}")
    
    return jsonify({'message': 'Friend deleted'})

# ---------- 聊天消息 API ----------


@social_bp.route('/api/chat/conversations', methods=['GET'])
async def list_conversations():
    """获取会话列表"""
    _oerr = await _oauth_ensure_user(['chat:read'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 获取好友列表（含受保护标记与管理员标记，供前端置顶「通知」会话）
    friends = await async_db_query(
        """SELECT f.friend_uid as uid, f.friend_name as user_name,
                  COALESCE(f.is_protected, 0) as is_protected,
                  COALESCE(u.is_admin, 0) as is_admin
           FROM friends f
           LEFT JOIN users u ON u.uid = f.friend_uid
           WHERE f.user_uid = ? AND f.status = 'accepted'""",
        (user['uid'],)
    )

    # 一次性取回所有未读数，避免 N+1 查询
    unread_rows = await async_db_query(
        """SELECT from_uid, COUNT(*) as cnt FROM chat_messages
           WHERE to_uid = ? AND COALESCE(is_read, 0) = 0
           GROUP BY from_uid""",
        (user['uid'],)
    ) or []
    unread_map = {r['from_uid']: r['cnt'] for r in unread_rows}

    # 为每个好友获取最后一条消息
    conversations = []
    for friend in friends:
        last_msg = await async_db_query(
            """SELECT * FROM chat_messages 
               WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)
               ORDER BY created_at DESC LIMIT 1""",
            (user['uid'], friend['uid'], friend['uid'], user['uid'])
        )

        conversations.append({
            'friend_uid': friend['uid'],
            'friend_name': friend['user_name'],
            'is_protected': bool(friend.get('is_protected')),
            'is_admin': bool(friend.get('is_admin')),
            'last_message': last_msg[0] if last_msg else None,
            'unread_count': unread_map.get(friend['uid'], 0)
        })

    # 注入与系统虚拟用户（UID 池 0~15）的会话：有消息往来才出现，免好友关系
    try:
        sys_uids = list(_su.SYSTEM_USERS.keys())
        for s_uid in sys_uids:
            s_last = await async_db_query(
                """SELECT * FROM chat_messages
                   WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)
                   ORDER BY created_at DESC LIMIT 1""",
                (user['uid'], s_uid, s_uid, user['uid'])
            )
            s_unread = unread_map.get(s_uid, 0)
            if not s_last and not s_unread:
                continue  # 无消息往来不出现在会话列表
            _uname, display = _su.get_system_user(s_uid)
            conversations.append({
                'friend_uid': s_uid,
                'friend_name': display,
                'is_protected': True,
                'is_admin': False,
                'is_system': True,
                'last_message': s_last[0] if s_last else None,
                'unread_count': s_unread
            })
    except Exception as e:
        logging.warning(f'inject system conversations failed: {e}')

    # 排序：受保护的通知渠道置顶，其余按最后消息时间倒序
    conversations.sort(
        key=lambda x: (
            0 if x['is_protected'] else 1,
            _neg_time_key(x['last_message']['created_at'] if x['last_message'] else '')
        )
    )
    
    return jsonify({'conversations': conversations})



@social_bp.route('/api/chat/messages/<message_id>/revoke', methods=['POST'])
async def revoke_message(message_id):
    """撤回消息（只能撤回自己发送的，2分钟内）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 查询消息
    msg = await async_db_query(
        "SELECT * FROM chat_messages WHERE message_id = ?",
        (message_id,),
        fetch_one=True
    )
    
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
    
    # 只能撤回自己发送的消息
    if msg['from_uid'] != user['uid']:
        return jsonify({'error': 'Can only revoke your own messages'}), 403
    
    # 只能撤回 text 类型的消息
    if msg['type'] not in ['text', 'recalled']:
        return jsonify({'error': 'This type of message cannot be revoked'}), 400
    
    # 已经撤回的不能再撤回
    if msg['type'] == 'recalled':
        return jsonify({'error': 'Message already revoked'}), 400
    
    # 时间限制：2分钟内
    from datetime import datetime, timedelta
    created_at = datetime.strptime(msg['created_at'], '%Y-%m-%d %H:%M:%S')
    now = datetime.now()
    if now - created_at > timedelta(minutes=2):
        return jsonify({'error': 'Can only revoke within 2 minutes'}), 400
    
    # 撤回消息（标记为已撤回，不删除）
    await async_db_query(
        "UPDATE chat_messages SET content = '消息已撤回', type = 'recalled' WHERE message_id = ?",
        (message_id,)
    )
    
    logging.info(f"Message revoked: {message_id} by user {user['user_name']}")
    
    return jsonify({'message': 'Message revoked successfully'}), 200



@social_bp.route('/api/chat/messages/<friend_uid>', methods=['GET'])
async def get_chat_messages(friend_uid):
    """获取与某好友的聊天记录"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否是好友（系统虚拟用户免好友关系：会话由系统通知自动建立）
    if not _su.is_system_uid(friend_uid):
        friends = await async_db_query(
            "SELECT id FROM friends WHERE user_uid = ? AND friend_uid = ? AND status = 'accepted'",
            (user['uid'], friend_uid)
        )
        if not friends:
            return jsonify({'error': 'Not friends'}), 403

    # 获取分页参数
    page = int(request.args.get('page', 1))
    page_size = min(int(request.args.get('page_size', 50)), 200)
    offset = (page - 1) * page_size

    # 获取消息（按时间倒序，然后前端反转显示）
    messages = await async_db_query(
        """SELECT * FROM chat_messages 
           WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?""",
        (user['uid'], friend_uid, friend_uid, user['uid'], page_size, offset)
    )
    
    # 反转顺序，按时间正序
    messages.reverse()
    
    # 标记对方发来的消息为已读（is_read 为统一未读口径；红包/转账的 status 保持原语义不动）
    await async_db_query(
        """UPDATE chat_messages 
           SET is_read = 1, read_at = CURRENT_TIMESTAMP
           WHERE from_uid = ? AND to_uid = ? AND COALESCE(is_read, 0) = 0""",
        (friend_uid, user['uid'])
    )
    await async_db_query(
        """UPDATE chat_messages 
           SET status = 'read'
           WHERE from_uid = ? AND to_uid = ? AND status = 'sent'
             AND type IN ('text', 'system', 'announcement', 'recalled')""",
        (friend_uid, user['uid'])
    )
    
    # 获取总数
    total_result = await async_db_query(
        """SELECT COUNT(*) as cnt FROM chat_messages 
           WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)""",
        (user['uid'], friend_uid, friend_uid, user['uid'])
    )
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'messages': messages,
        'total': total,
        'page': page,
        'page_size': page_size
    })


@social_bp.route('/api/chat/send', methods=['POST'])
async def send_message():
    """发送文本消息"""
    # 限流检查
    allowed, remaining = _check_rate_limit('chat')
    if not allowed:
        return jsonify({'error': 'Too many messages, please slow down'}), 429
    
    _oerr = await _oauth_ensure_user(['chat:write'])
    if _oerr:
        return _oerr
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否被封禁
    is_banned, ban_msg = await _is_user_banned(user)
    if is_banned:
        return jsonify({'error': f'Account banned: {ban_msg}'}), 403
    
    data = await request.get_json() or {}
    to_uid = data.get('to_uid', '').strip()
    content = data.get('content', '').strip()

    if not to_uid:
        return jsonify({'error': 'Recipient UID required'}), 400
    if not content:
        return jsonify({'error': 'Message content required'}), 400

    # 输入净化：防御聊天消息中的存储型 XSS
    content = _sanitize_user_content(content)
    
    # 长度限制
    if len(content) > 2000:
        return jsonify({'error': 'Message too long (max 2000 chars)'}), 400
    
    # 检查是否是好友（系统虚拟用户免好友关系；回复系统消息不报 403）
    if not _su.is_system_uid(to_uid):
        friends = await async_db_query(
            "SELECT id FROM friends WHERE user_uid = ? AND friend_uid = ? AND status = 'accepted'",
            (user['uid'], to_uid)
        )
        if not friends:
            return jsonify({'error': 'Not friends'}), 403

    # 获取对方用户名
    target_users = await async_db_query(
        "SELECT user_name FROM users WHERE uid = ?",
        (to_uid,)
    )
    if not target_users:
        # 对方账号已注销，但好友关系残留：清理悬空引用，避免持续报错
        if not _su.is_system_uid(to_uid):
            await async_db_query(
                "DELETE FROM friends WHERE (user_uid = ? AND friend_uid = ?) OR (user_uid = ? AND friend_uid = ?)",
                (user['uid'], to_uid, to_uid, user['uid'])
            )
        return jsonify({'error': '对方账号已注销'}), 404
    
    target_name = target_users[0]['user_name']
    
    # 创建消息
    msg_id = _generate_message_id()
    await async_db_query(
        """INSERT INTO chat_messages 
           (message_id, from_uid, from_name, to_uid, to_name, content, type, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'text', 'sent', CURRENT_TIMESTAMP)""",
        (msg_id, user['uid'], user['user_name'], to_uid, target_name, content)


    )

    # 触发钩子事件：发送聊天消息
    await fire_event('MESSAGE_SEND', trigger_user=user['uid'], target_user=to_uid, content=content)

    return jsonify({
        'message_id': msg_id,
        'status': 'sent',
        'created_at': None  # 前端可以自己获取
    }), 201


@social_bp.route('/api/chat/message/<message_id>/recall', methods=['POST'])
async def recall_message(message_id):
    """撤回消息（只能撤回自己发的，2分钟内）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # 查询消息
    msg = await async_db_query(
        "SELECT * FROM chat_messages WHERE message_id = ?",
        (message_id,),
        fetch_one=True
    )

    if not msg:
        return jsonify({'error': 'Message not found'}), 404

    # 只能撤回自己发的消息
    if msg['from_uid'] != user['uid']:
        return jsonify({'error': 'Permission denied'}), 403

    # 只能撤回 text 类型的消息
    if msg['type'] not in ['text', 'recalled']:
        return jsonify({'error': 'This type of message cannot be recalled'}), 400

    # 已经撤回的不能再撤回
    if msg['type'] == 'recalled':
        return jsonify({'error': 'Message already recalled'}), 400

    # 时间限制：2分钟内
    from datetime import datetime, timedelta
    created_at = datetime.strptime(msg['created_at'], '%Y-%m-%d %H:%M:%S')
    now = datetime.now()
    if now - created_at > timedelta(minutes=2):
        return jsonify({'error': 'Can only recall within 2 minutes'}), 400

    # 撤回消息
    await async_db_query(
        "UPDATE chat_messages SET content = '消息已撤回', type = 'recalled' WHERE message_id = ?",
        (message_id,)
    )

    logging.info(f"Message recalled: {message_id} by {user['user_name']}")

    return jsonify({'message': 'Message recalled successfully'}), 200



async def _build_unread_payload(uid: str) -> dict:
    """计算未读快照（未读消息总数、按发送者分组、公告未读、待处理好友请求）。

    供 /api/chat/unread（轮询兜底）与 /api/chat/stream（SSE）复用。
    """
    rows = await async_db_query(
        """SELECT from_uid, from_name, type, COUNT(*) as cnt
           FROM chat_messages
           WHERE to_uid = ? AND COALESCE(is_read, 0) = 0
           GROUP BY from_uid, from_name, type""",
        (uid,)
    ) or []

    total = 0
    by_user = {}
    announcement_unread = 0
    for r in rows:
        cnt = r['cnt'] or 0
        total += cnt
        key = r['from_uid']
        if key not in by_user:
            by_user[key] = {'from_uid': key, 'from_name': r['from_name'], 'count': 0}
        by_user[key]['count'] += cnt
        if r['type'] == 'announcement':
            announcement_unread += cnt

    # 待处理好友请求数（一并返回，前端可在「好友」入口显示红点）
    fr = await async_db_query(
        "SELECT COUNT(*) as cnt FROM friends WHERE friend_uid = ? AND status = 'pending'",
        (uid,)
    )
    friend_requests_pending = fr[0]['cnt'] if fr else 0

    return {
        'unread_count': total,
        'total': total,
        'announcement_unread': announcement_unread,
        'friend_requests': friend_requests_pending,
        'by_user': sorted(by_user.values(), key=lambda x: -x['count']),
    }


@social_bp.route('/api/chat/unread', methods=['GET'])
async def get_unread_count():
    """获取未读消息总数（含按发送者分组明细与公告未读数，供导航栏红点使用）。"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(await _build_unread_payload(user['uid']))


@social_bp.route('/api/chat/stream', methods=['GET'])
async def chat_events_stream():
    """SSE 长连接：实时推送未读消息/好友请求变化（替代前端每 15s 轮询 /api/chat/unread）。

    客户端用 EventSource('/api/chat/stream') 连接，收到 `data: {json}\\n\\n` 事件后刷新红点，
    并由前端广播到聊天页做消息实时刷新。服务端每 3s 重算一次快照，仅在变化时推送，避免无效流量。
    GET 请求豁免 CSRF；客户端关闭连接即结束。
    """
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    uid = user['uid']

    async def gen():
        last = None
        while True:
            try:
                if await request.is_disconnected():
                    break
            except Exception:
                break
            try:
                payload = await _build_unread_payload(uid)
                s = json.dumps(payload, ensure_ascii=False)
            except Exception:
                s = None
            if s is not None and s != last:
                last = s
                yield 'data: ' + s + '\n\n'
            await asyncio.sleep(3)

    return Response(
        gen(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache, no-transform',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )


async def _build_userinfo_payload(owner: str) -> dict:
    """构建用户信息快照（供 SSE userinfo 事件复用，避免前端每页 fetch /userinfo）。

    payload 形状与 GET /userinfo 完全一致，便于前端无差别消费。
    """
    user = await async_db_query(
        "SELECT user_name, balence, apikeys, uid, created_at, is_admin, is_banned, ban_reason, ban_expire_at, max_overdraft, must_change_password FROM users WHERE user_name = ?",
        (owner,)
    )
    if not user:
        return None
    info = user[0]
    is_banned, ban_msg = await _is_user_banned(info)
    return {
        'username': info['user_name'],
        'uid': info.get('uid'),
        'balence': info['balence'],
        'max_overdraft': info.get('max_overdraft', 0) or 0,
        'created_at': info.get('created_at'),
        'apikeys': info['apikeys'].split(',') if info['apikeys'] else [],
        'is_admin': bool(info.get('is_admin', 0)),
        'must_change_password': bool(info.get('must_change_password', 0)),
        'is_banned': is_banned,
        'ban_reason': ban_msg if is_banned else ''
    }


@social_bp.route('/api/stream', methods=['GET'])
async def unified_events_stream():
    """统一 SSE 长连接：以具名事件推送未读、用户信息、通知列表，替代前端每页 fetch('/userinfo')、
    每 15s 轮询 /api/chat/unread 与每 30s 轮询 /api/notifications，显著降低访问日志噪音与服务端请求量。

    客户端用 EventSource('/api/stream') 订阅，按 event 名分发：
      event: unread        data: {未读快照}        -> 红点（复用 applyUnread）
      event: userinfo      data: {余额/用户名/UID/管理员标记...} -> 导航栏 + 各页面
      event: notifications data: {通知列表 + 未读数} -> 右上角通知铃铛
    服务端每 3s 重算快照，仅在变化时推送，避免无效流量。GET 请求天然豁免 CSRF。
    """
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    owner = session['user']
    uid = user['uid']

    async def gen():
        last_unread = None
        last_userinfo = None
        last_notifs = None
        while True:
            try:
                if await request.is_disconnected():
                    break
            except Exception:
                break
            # 未读快照
            try:
                payload = await _build_unread_payload(uid)
                s = json.dumps(payload, ensure_ascii=False)
                if s != last_unread:
                    last_unread = s
                    yield 'event: unread\ndata: ' + s + '\n\n'
            except Exception:
                pass
            # 用户信息快照（余额/用户名/管理员标记等变化时推送）
            try:
                info = await _build_userinfo_payload(owner)
                if info:
                    s2 = json.dumps(info, ensure_ascii=False)
                    if s2 != last_userinfo:
                        last_userinfo = s2
                        yield 'event: userinfo\ndata: ' + s2 + '\n\n'
            except Exception:
                pass
            # 通知快照（铃铛列表 + 未读数，变化时推送）
            try:
                items = await _ntf.get_notifications(uid, limit=20)
                n_unread = await _ntf.unread_count(uid)
                s3 = json.dumps({'notifications': items, 'unread_count': n_unread},
                                ensure_ascii=False, default=str)
                if s3 != last_notifs:
                    last_notifs = s3
                    yield 'event: notifications\ndata: ' + s3 + '\n\n'
            except Exception:
                pass
            await asyncio.sleep(3)

    return Response(
        gen(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache, no-transform',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )


@social_bp.route('/api/chat/read/<friend_uid>', methods=['POST'])
async def mark_conversation_read(friend_uid):
    """把与某好友的会话全部标记为已读（前端点开会话时调用）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    n = await async_db_query(
        """UPDATE chat_messages SET is_read = 1, read_at = CURRENT_TIMESTAMP
           WHERE from_uid = ? AND to_uid = ? AND COALESCE(is_read, 0) = 0""",
        (friend_uid, user['uid'])
    )
    return jsonify({'message': 'marked', 'count': n})

# ---------- 红包/转账 API ----------


@social_bp.route('/api/chat/transfer', methods=['POST'])
async def send_transfer():
    """发送转账（用账户余额）"""
    # 限流检查
    allowed, remaining = _check_rate_limit('transfer')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429
    
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否被封禁
    is_banned, ban_msg = await _is_user_banned(user)
    if is_banned:
        return jsonify({'error': f'Account banned: {ban_msg}'}), 403
    
    data = await request.get_json() or {}
    to_uid = data.get('to_uid', '').strip()
    amount = data.get('amount', 0.0)
    password = data.get('password', '')
    remark = data.get('remark', '').strip()
    
    if not to_uid:
        return jsonify({'error': 'Recipient UID required'}), 400
    if not amount or amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    if not password:
        return jsonify({'error': 'Password required for confirmation'}), 400
    
    # 金额限制
    if amount > 1000:
        return jsonify({'error': 'Maximum transfer amount is 1000'}), 400
    
    # 验证密码
    if not verify_password(password, user['user_password']):
        return jsonify({'error': 'Password incorrect'}), 400
    
    # 检查余额
    if user['balence'] < amount:
        return jsonify({'error': 'Insufficient balence'}), 400
    
    # 检查是否是好友
    friends = await async_db_query(
        "SELECT id FROM friends WHERE user_uid = ? AND friend_uid = ? AND status = 'accepted'",
        (user['uid'], to_uid)
    )
    if not friends:
        return jsonify({'error': 'Not friends'}), 403
    
    # 获取对方用户信息
    target_users = await async_db_query(
        "SELECT uid, user_name, balence FROM users WHERE uid = ?",
        (to_uid,)
    )
    if not target_users:
        return jsonify({'error': 'Recipient not found'}), 404
    
    target_user = target_users[0]
    
    # 执行转账（在事务中）
    def _do_transfer():
        conn = _get_conn()
        try:
            db.begin_write(conn)
            cur = conn.cursor()
            
            # 重新检查余额（防止并发）
            cur.execute("SELECT balence FROM users WHERE uid = ?", (user['uid'],))
            current_balence = cur.fetchone()['balence']
            if current_balence < amount:
                conn.rollback()
                return False, 'Insufficient balence', None, None
            
            # 扣除发送方余额
            new_sender_balence = round(current_balence - amount, 6)
            cur.execute(
                "UPDATE users SET balence = ? WHERE uid = ?",
                (new_sender_balence, user['uid'])
            )
            
            # 增加接收方余额
            new_receiver_balence = round(target_user['balence'] + amount, 6)
            cur.execute(
                "UPDATE users SET balence = ? WHERE uid = ?",
                (new_receiver_balence, to_uid)
            )
            
            # 创建转账消息
            msg_id = _generate_message_id()
            msg_content = remark if remark else f'转账 {amount:.2f} 元'
            cur.execute(
                """INSERT INTO chat_messages 
                   (message_id, from_uid, from_name, to_uid, to_name, content, type, amount, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'transfer', ?, 'sent', CURRENT_TIMESTAMP)""",
                (msg_id, user['uid'], user['user_name'], to_uid, target_user['user_name'], 
                 msg_content, amount)
            )
            
            # 记录发送方交易
            tx_id_sender = _generate_transaction_id()
            cur.execute(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'transfer_out', ?, ?, ?, ?)""",
                (tx_id_sender, user['uid'], user['user_name'], -amount, new_sender_balence, 
                 msg_id, f'转账给 {target_user["user_name"]}')
            )
            
            # 记录接收方交易
            tx_id_receiver = _generate_transaction_id()
            cur.execute(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'transfer_in', ?, ?, ?, ?)""",
                (tx_id_receiver, to_uid, target_user['user_name'], amount, new_receiver_balence,
                 msg_id, f'收到 {user["user_name"]} 转账')
            )
            
            conn.commit()
            return True, 'Transfer successful', msg_id, new_sender_balence

        except Exception as e:
            conn.rollback()
            return False, str(e), None, None
        finally:
            conn.close()  # 归还连接池：finally 兜底，覆盖余额不足的提前 return
    
    success, msg, msg_id, new_balence = await asyncio.to_thread(_do_transfer)
    
    if not success:
        return jsonify({'error': msg}), 400
    
    logging.info(f"Transfer: {user['user_name']} -> {target_user['user_name']}, amount: {amount}")

    # 触发钩子事件：好友转账
    await fire_event('TRANSFER', trigger_user=user['uid'], target_user=to_uid, amount=amount)

    return jsonify({
        'message': 'Transfer successful',
        'message_id': msg_id,
        'amount': amount,
        'new_balence': new_balence
    }), 201


@social_bp.route('/api/chat/redpacket', methods=['POST'])
async def send_redpacket():
    """发送红包（用账户余额）"""
    # 限流检查
    allowed, remaining = _check_rate_limit('transfer')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429
    
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查是否被封禁
    is_banned, ban_msg = await _is_user_banned(user)
    if is_banned:
        return jsonify({'error': f'Account banned: {ban_msg}'}), 403
    
    data = await request.get_json() or {}
    to_uid = data.get('to_uid', '').strip()
    amount = data.get('amount', 0.0)
    password = data.get('password', '')
    remark = data.get('remark', '').strip()
    
    if not to_uid:
        return jsonify({'error': 'Recipient UID required'}), 400
    if not amount or amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    if not password:
        return jsonify({'error': 'Password required for confirmation'}), 400
    
    # 金额限制
    if amount > 200:
        return jsonify({'error': 'Maximum red packet amount is 200'}), 400
    
    # 验证密码
    if not verify_password(password, user['user_password']):
        return jsonify({'error': 'Password incorrect'}), 400
    
    # 检查余额
    if user['balence'] < amount:
        return jsonify({'error': 'Insufficient balence'}), 400
    
    # 检查是否是好友
    friends = await async_db_query(
        "SELECT id FROM friends WHERE user_uid = ? AND friend_uid = ? AND status = 'accepted'",
        (user['uid'], to_uid)
    )
    if not friends:
        return jsonify({'error': 'Not friends'}), 403
    
    # 获取对方用户信息
    target_users = await async_db_query(
        "SELECT uid, user_name, balence FROM users WHERE uid = ?",
        (to_uid,)
    )
    if not target_users:
        return jsonify({'error': 'Recipient not found'}), 404
    
    target_user = target_users[0]
    
    # 执行红包发送（先扣除余额，对方领取时再增加）
    def _do_redpacket():
        conn = _get_conn()
        try:
            db.begin_write(conn)
            cur = conn.cursor()
            
            # 重新检查余额
            cur.execute("SELECT balence FROM users WHERE uid = ?", (user['uid'],))
            current_balence = cur.fetchone()['balence']
            if current_balence < amount:
                conn.rollback()
                return False, 'Insufficient balence', None, None
            
            # 扣除发送方余额
            new_sender_balence = round(current_balence - amount, 6)
            cur.execute(
                "UPDATE users SET balence = ? WHERE uid = ?",
                (new_sender_balence, user['uid'])
            )
            
            # 创建红包消息（未领取状态）
            msg_id = _generate_message_id()
            msg_content = remark if remark else f'红包 {amount:.2f} 元'
            cur.execute(
                """INSERT INTO chat_messages 
                   (message_id, from_uid, from_name, to_uid, to_name, content, type, amount, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'redpacket', ?, 'sent')""",
                (msg_id, user['uid'], user['user_name'], to_uid, target_user['user_name'], 
                 msg_content, amount)
            )
            
            # 记录发送方交易
            tx_id_sender = _generate_transaction_id()
            cur.execute(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'redpacket_send', ?, ?, ?, ?)""",
                (tx_id_sender, user['uid'], user['user_name'], -amount, new_sender_balence, 
                 msg_id, f'发红包给 {target_user["user_name"]}')
            )
            
            conn.commit()
            return True, 'Red packet sent', msg_id, new_sender_balence

        except Exception as e:
            conn.rollback()
            return False, str(e), None, None
        finally:
            conn.close()  # 归还连接池：finally 兜底，覆盖余额不足的提前 return
    
    success, msg, msg_id, new_balence = await asyncio.to_thread(_do_redpacket)
    
    if not success:
        return jsonify({'error': msg}), 400
    
    logging.info(f"Red packet: {user['user_name']} -> {target_user['user_name']}, amount: {amount}")

    # 触发钩子事件：发送红包
    await fire_event('REDPACKET', trigger_user=user['uid'], target_user=to_uid, amount=amount)

    return jsonify({
        'message': 'Red packet sent',
        'message_id': msg_id,
        'amount': amount,
        'new_balence': new_balence
    }), 201


@social_bp.route('/api/chat/redpacket/<message_id>/claim', methods=['POST'])
async def claim_redpacket(message_id):
    """领取红包"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user = await _get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 检查红包消息是否存在且是发给当前用户的
    messages = await async_db_query(
        "SELECT * FROM chat_messages WHERE message_id = ? AND to_uid = ? AND type = 'redpacket'",
        (message_id, user['uid'])
    )
    
    if not messages:
        return jsonify({'error': 'Red packet not found'}), 404
    
    msg = messages[0]
    
    if msg['status'] == 'claimed':
        return jsonify({'error': 'Red packet already claimed'}), 400
    
    if msg['status'] == 'expired':
        return jsonify({'error': 'Red packet expired'}), 400
    
    # 执行领取
    def _do_claim():
        conn = _get_conn()
        try:
            db.begin_write(conn)
            cur = conn.cursor()
            
            # 重新检查状态
            cur.execute(
                "SELECT status FROM chat_messages WHERE message_id = ?",
                (message_id,)
            )
            current_status = cur.fetchone()['status']
            if current_status != 'sent':
                conn.rollback()
                return False, 'Red packet already claimed or expired', None
            
            amount = msg['amount']
            
            # 更新消息状态为已领取
            cur.execute(
                "UPDATE chat_messages SET status = 'claimed', claimed_at = CURRENT_TIMESTAMP WHERE message_id = ?",
                (message_id,)
            )
            
            # 增加接收方余额
            cur.execute("SELECT balence FROM users WHERE uid = ?", (user['uid'],))
            current_balence = cur.fetchone()['balence']
            new_balence = round(current_balence + amount, 6)
            cur.execute(
                "UPDATE users SET balence = ? WHERE uid = ?",
                (new_balence, user['uid'])
            )
            
            # 记录接收方交易
            tx_id = _generate_transaction_id()
            cur.execute(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, ?, ?, 'redpacket_recv', ?, ?, ?, ?)""",
                (tx_id, user['uid'], user['user_name'], amount, new_balence,
                 message_id, f'收到 {msg["from_name"]} 的红包')
            )
            
            conn.commit()
            return True, 'Red packet claimed', new_balence

        except Exception as e:
            conn.rollback()
            return False, str(e), None
        finally:
            conn.close()

    success, result_msg, new_balence = await asyncio.to_thread(_do_claim)
    
    if not success:
        return jsonify({'error': result_msg}), 400
    
    logging.info(f"Red packet claimed: {msg['from_name']} -> {user['user_name']}, amount: {msg['amount']}")

    # 触发钩子事件：领取红包
    await fire_event('REDPACKET_CLAIM', trigger_user=user['uid'], target_user=msg['from_uid'], amount=msg['amount'])

    return jsonify({
        'message': 'Red packet claimed',
        'amount': msg['amount'],
        'new_balence': new_balence
    })

# ---------- 余额变动记录 API ----------


@social_bp.route('/community')
async def community():
    """社区广场页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('community.html')



@social_bp.route('/social/post/create')
async def create_post_page():
    """发帖页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_create_post.html')


@social_bp.route('/social/post/<post_id>')
async def post_detail_page(post_id):
    """帖子详情页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_post_detail.html', post_id=post_id)


@social_bp.route('/social/collections')
async def my_collections_page():
    """我的收藏页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_collections.html')


@social_bp.route('/social/friends')
async def friends_page():
    """好友列表页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_friends.html')


@social_bp.route('/social/friends/requests')
@social_bp.route('/social/friend_requests')
async def friend_requests_page():
    """好友请求页面（/social/friend_requests 为兼容别名，避免旧链接 404）"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_friend_requests.html')


@social_bp.route('/social/chat')
async def chat_page():
    """聊天页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_chat.html')


@social_bp.route('/social/transfer')
async def transfer_page():
    """转账/红包页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_transfer.html')


@social_bp.route('/social/transactions')
async def transactions_page():
    """交易记录页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_transactions.html')


