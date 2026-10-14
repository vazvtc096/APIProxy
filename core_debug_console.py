"""Debug Console 远程控制台：密钥管理、命令执行、双重认证。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
import os
import logging

from quart import request, jsonify, session

from .apikey import _get_user_by_name, verify_password
from .configs import DEBUG_CONSOLE_ENABLED
from .core_db import _get_conn
from .core_net_utils import _ip_in_cidr
from .core_security_utils import _is_safe_username, MIN_PASSWORD_LENGTH

DEBUG_CONSOLE_KEY_LENGTH = 128  # Debug Console 密钥位数（字节）

def _init_debug_console_table():
    """初始化 Debug Console 配置表 + 多密钥表"""
    def _init():
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS debug_console_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    debug_console_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_refreshed_at TIMESTAMP
                )
            """)
            # 多密钥表：供管理端 /api/admin/debug-console-keys 与 Debug Console `list/create/revoke_debug_console_key`
            # 命令使用。历史版本漏建此表，导致相关接口一律 500（P0-01 重构期发现并修复）。
            cur.execute("""
                CREATE TABLE IF NOT EXISTS debug_console_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP,
                    last_used_ip TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
            """)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_debug_console_keys_hash_active "
                "ON debug_console_keys(key_hash, is_active)")
            conn.commit()
            
            # 检查是否已有密钥，没有则生成
            cur.execute("SELECT debug_console_key FROM debug_console_config WHERE id = 1")
            row = cur.fetchone()
            if not row:
                # 第一次启动，生成密钥
                import base64
                key_bytes = os.urandom(DEBUG_CONSOLE_KEY_LENGTH)
                debug_console_key = base64.b64encode(key_bytes).decode('ascii')
                cur.execute(
                    "INSERT INTO debug_console_config (id, debug_console_key, last_refreshed_at) VALUES (1, ?, CURRENT_TIMESTAMP)",
                    (debug_console_key,)
                )
                conn.commit()
                print(f"[Debug Console] 首次启动，已生成 Debug Console 密钥")
                print(f"[Debug Console] 密钥前8位: {debug_console_key[:8]}...（完整密钥仅存于数据库 debug_console_config 表，未打印到日志）")
                print(f"[Debug Console] 请妥善保管，丢失后无法找回！")
    _init()


def _legacy_debug_console_config_key() -> str | None:
    """读取历史 debug_console_config 表中的密钥（仅用于一次性迁移）。"""
    try:
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT debug_console_key FROM debug_console_config WHERE id = 1")
            row = cur.fetchone()
            return row['debug_console_key'] if row else None
    except Exception:
        return None


def _get_debug_console_key_sync() -> str:
    """获取当前 Debug Console 密钥（同步版本）。

    单一数据源为 system_config['debug_console_key'] —— 即 debug_console.py 中 TCP Debug Console 服务所用、
    且启动日志打印的那把密钥。历史实现改读 debug_console_config 表，而该表从未被写入
    （_init_debug_console_table 从未被调用），导致 HTTP Debug Console API 的密钥校验恒为失败、
    19 条 /api/debug-console/* 路由全部 403。此处统一委托给 debug_console.py，并在首次调用时
    把遗留的 debug_console_config 密钥迁移过去，避免老部署换密钥。
    """
    from . import debug_console as _debug_console
    key = _debug_console._get_config('debug_console_key')
    if key:
        return key
    legacy = _legacy_debug_console_config_key()
    if legacy:
        _debug_console._set_config('debug_console_key', legacy)
        logging.info("[Debug Console] 已将 debug_console_config 中的遗留密钥迁移至 system_config")
        return legacy
    # 两处均无：由 debug_console.py 生成并落库（与 TCP 服务共用同一把）
    return _debug_console.get_debug_console_key()


def _refresh_debug_console_key_sync() -> str:
    """刷新 Debug Console 密钥（同步版本），写入 system_config 以与 TCP Debug Console 服务保持一致。

    Returns:
        新密钥
    """
    from . import debug_console as _debug_console
    new_key = _debug_console.generate_debug_console_key()
    # 同步清理遗留表，防止后续再从旧位置读到过期密钥
    try:
        conn = _get_conn()
        with conn:
            conn.execute(
                "UPDATE debug_console_config SET debug_console_key = ?, "
                "last_refreshed_at = CURRENT_TIMESTAMP WHERE id = 1",
                (new_key,))
            conn.commit()
    except Exception:
        pass
    logging.warning("[Debug Console] 密钥已刷新")
    return new_key


def _verify_debug_console_key_sync(key: str) -> bool:
    """验证 Debug Console 密钥（同步版本）"""
    if not key or not DEBUG_CONSOLE_ENABLED:
        return False
    
    current_key = _get_debug_console_key_sync()
    if not current_key:
        return False
    
    # 使用恒定时间比较，防止时序攻击
    import hmac
    return hmac.compare_digest(key, current_key)


async def _get_debug_console_key() -> str:
    """获取当前 Debug Console 密钥（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_get_debug_console_key_sync)


async def _refresh_debug_console_key() -> str:
    """刷新 Debug Console 密钥（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_refresh_debug_console_key_sync)


async def _verify_debug_console_key(key: str) -> bool:
    """验证 Debug Console 密钥（异步版本）"""
    import asyncio
    return await asyncio.to_thread(_verify_debug_console_key_sync, key)


def _generate_debug_console_key_sync(key_name: str = "default") -> str:
    """生成新的 Debug Console 密钥（同步版本）
    Returns:
        明文密钥（只返回一次，数据库只存哈希）
    """
    import os
    import base64
    import hashlib
    
    # 128位 = 16字节
    key_bytes = os.urandom(16)
    key_b64 = base64.b64encode(key_bytes).decode('ascii')
    
    # 存哈希，不存明文
    key_hash = hashlib.sha256(key_b64.encode('utf-8')).hexdigest()
    
    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO debug_console_keys (key_hash, key_name) VALUES (?, ?)",
            (key_hash, key_name)
        )
        conn.commit()
    
    return key_b64


def _validate_debug_console_key_sync(key_b64: str, ip: str = "") -> bool:
    """验证 Debug Console 密钥是否有效（同步版本）"""
    if not key_b64:
        return False
    
    import hashlib
    import datetime
    
    key_hash = hashlib.sha256(key_b64.encode('utf-8')).hexdigest()
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM debug_console_keys WHERE key_hash = ? AND is_active = 1",
            (key_hash,)
        )
        row = cur.fetchone()
        
        if row:
            # 更新最后使用时间
            cur.execute(
                "UPDATE debug_console_keys SET last_used_at = ?, last_used_ip = ? WHERE key_hash = ?",
                (now, ip, key_hash)
            )
            conn.commit()
            return True
    
    return False


def _list_debug_console_keys_sync() -> list:
    """列出所有 Debug Console 密钥（同步版本，不返回明文）"""
    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, key_name, created_at, last_used_at, last_used_ip, is_active
            FROM debug_console_keys ORDER BY created_at DESC
        """)
        rows = cur.fetchall()
        return [dict(row) for row in rows]


def _revoke_debug_console_key_sync(key_id: int) -> bool:
    """撤销 Debug Console 密钥（同步版本）"""
    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE debug_console_keys SET is_active = 0 WHERE id = ?",
            (key_id,)
        )
        conn.commit()
        return cur.rowcount > 0
def _debug_console_cmd_help(conn, cur, args) -> dict:
    output = """可用命令：
  help                           显示帮助
  status                         服务器状态
  stats                          统计信息

  用户管理：
    list_users [page]            列出用户
    get_user <username>          获取用户信息
    create_user <user> <pass> [balence]  创建用户
    delete_user <username>      删除用户
    ban_user <user> <reason> [days]    封禁用户
    unban_user <username>        解封用户
    set_balence <user> <amount>  设置余额
    add_balence <user> <amount>  增加余额

  充值管理：
    list_recharges [status]      列出充值请求
    approve_recharge <id>        通过充值
    reject_recharge <id> [reason]  拒绝充值

  会话管理：
    list_sessions <username>     查看用户活跃会话
    kick_session <session_id>    踢掉指定会话
    kick_all_sessions <username> 踢掉用户所有会话
    cleanup_sessions             清理过期会话

  API Key 管理：
    list_apikeys <username>      列出用户 API Key
    gen_apikey <username>        生成 API Key
    revoke_apikey <user> <key>   吊销 API Key

  Debug Console 密钥管理：
    list_debug_console_keys               列出 Debug Console 密钥
    gen_debug_console_key [name]          生成新 Debug Console 密钥
    revoke_debug_console_key <id>         撤销 Debug Console 密钥

  IP 白名单管理（仅 Debug Console 可控制）：
    whitelist add <ip> [note] [bypass]   加入白名单（bypass 默认 all，可选 blacklist/autoban/account_ban/ratelimit/device_ban 组合）
    whitelist remove <ip>                移除白名单
    whitelist list                       列出白名单
    whitelist check <ip>                 检查 IP 是否命中白名单"""
    return {'success': True, 'output': output, 'data': {}}
            
            # ==================== 状态 ====================


def _debug_console_cmd_status(conn, cur, args) -> dict:
    cur.execute("SELECT COUNT(*) as cnt FROM users")
    user_count = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) as cnt FROM sessions WHERE expires_at > datetime('now')")
    session_count = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) as cnt FROM recharge_requests WHERE status = 'pending'")
    pending_recharges = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) as cnt FROM debug_console_keys WHERE is_active = 1")
    debug_console_keys = cur.fetchone()['cnt']
    
    output = f"""服务器状态：运行中
用户总数：{user_count}
活跃会话：{session_count}
待处理充值：{pending_recharges}
活跃 Debug Console 密钥：{debug_console_keys}"""
    return {'success': True, 'output': output, 'data': {
        'user_count': user_count,
        'session_count': session_count,
        'pending_recharges': pending_recharges,
        'debug_console_keys': debug_console_keys
    }}
            
            # ==================== 统计 ====================


def _debug_console_cmd_stats(conn, cur, args) -> dict:
    cur.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = cur.fetchone()['cnt']
    cur.execute("SELECT SUM(balence) as total FROM users")
    total_balence = cur.fetchone()['total'] or 0
    cur.execute("SELECT COUNT(*) as cnt FROM recharge_requests WHERE status = 'approved'")
    approved_recharges = cur.fetchone()['cnt']
    cur.execute("SELECT COUNT(*) as cnt FROM login_logs WHERE status = 'success' AND created_at > datetime('now', '-1 day')")
    logins_24h = cur.fetchone()['cnt']
    
    output = f"""统计信息：
总用户数：{total_users}
总余额：{total_balence:.6f} 元
已通过充值：{approved_recharges} 笔
24小时登录：{logins_24h} 次"""
    return {'success': True, 'output': output, 'data': {
        'total_users': total_users,
        'total_balence': total_balence,
        'approved_recharges': approved_recharges,
        'logins_24h': logins_24h
    }}
            
            # ==================== 用户列表 ====================


def _debug_console_cmd_list_users(conn, cur, args) -> dict:
    page = int(args[0]) if args else 1
    page_size = 20
    offset = (page - 1) * page_size
    
    cur.execute(
        "SELECT user_name, uid, balence, is_admin, is_banned, email, created_at FROM users ORDER BY id DESC LIMIT ? OFFSET ?",
        (page_size, offset)
    )
    users = cur.fetchall()
    
    cur.execute("SELECT COUNT(*) as cnt FROM users")
    total = cur.fetchone()['cnt']
    
    lines = [f"用户列表（第 {page} 页，共 {total} 个）："]
    for u in users:
        status = []
        if u['is_admin']:
            status.append('管理员')
        if u['is_banned']:
            status.append('已封禁')
        status_str = f" [{', '.join(status)}]" if status else ''
        lines.append(f"  {u['user_name']}  余额: {u['balence']:.6f}  邮箱: {u['email'] or '无'}{status_str}")
    
    output = '\n'.join(lines)
    return {'success': True, 'output': output, 'data': {'users': [dict(u) for u in users], 'total': total, 'page': page}}
            
            # ==================== 获取用户信息 ====================


def _debug_console_cmd_get_user(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：get_user <username>', 'data': {}}
    
    username = args[0]
    cur.execute("SELECT * FROM users WHERE user_name = ?", (username,))
    user = cur.fetchone()
    
    if not user:
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    # 统计 API Key 数量
    apikeys = user['apikeys'].split(',') if user['apikeys'] else []
    apikeys = [k for k in apikeys if k]
    
    # 统计活跃会话
    cur.execute("SELECT COUNT(*) as cnt FROM sessions WHERE user_name = ? AND expires_at > datetime('now')", (username,))
    sessions = cur.fetchone()['cnt']
    
    output = f"""用户信息：
  用户名：{user['user_name']}
  UID：{user['uid']}
  余额：{user['balence']:.6f} 元
  邮箱：{user['email'] or '未设置'}
  管理员：{'是' if user['is_admin'] else '否'}
  封禁：{'是' if user['is_banned'] else '否'}
  封禁原因：{user.get('ban_reason') or '无'}
  注册时间：{user['created_at']}
  最后登录IP：{user.get('last_login_ip') or '无'}
  最后登录时间：{user.get('last_login_time') or '无'}
  API Key 数量：{len(apikeys)}
  活跃会话：{sessions}
  最大设备数：{user.get('max_sessions', 1)}"""
    return {'success': True, 'output': output, 'data': dict(user)}
            
            # ==================== 创建用户 ====================


def _debug_console_cmd_create_user(conn, cur, args) -> dict:
    if len(args) < 2:
        return {'success': False, 'output': '用法：create_user <username> <password> [balence]', 'data': {}}
    
    username = args[0]
    password = args[1]
    balence = float(args[2]) if len(args) > 2 else 0.0

    # 用户名只允许字母、数字、下划线
    if not _is_safe_username(username):
        return {'success': False, 'output': '用户名只能包含字母、数字和下划线', 'data': {}}

    # 检查用户是否存在
    cur.execute("SELECT id FROM users WHERE user_name = ?", (username,))
    if cur.fetchone():
        return {'success': False, 'output': f'用户 {username} 已存在', 'data': {}}
    
    # 密码强度检查
    if len(password) < MIN_PASSWORD_LENGTH:
        return {'success': False, 'output': f'密码太短（至少 {MIN_PASSWORD_LENGTH} 位）', 'data': {}}
    if not any(c.isalpha() for c in password):
        return {'success': False, 'output': '密码必须包含至少一个字母', 'data': {}}
    if not any(c.isdigit() for c in password):
        return {'success': False, 'output': '密码必须包含至少一个数字', 'data': {}}
    
    import uuid
    import bcrypt
    
    uid = uuid.uuid4().hex[:12]
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    password_hash = hashed.decode('utf-8')
    
    cur.execute(
        "INSERT INTO users (user_name, user_password, apikeys, balence, uid, is_admin, email) VALUES (?, ?, '', ?, ?, 0, '')",
        (username, password_hash, balence, uid)
    )
    conn.commit()
    
    output = f"用户 {username} 创建成功\nUID: {uid}\n初始余额：{balence:.6f} 元"
    return {'success': True, 'output': output, 'data': {'username': username, 'uid': uid, 'balence': balence}}
            
            # ==================== 删除用户 ====================


def _debug_console_cmd_delete_user(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：delete_user <username>', 'data': {}}
    
    username = args[0]
    
    cur.execute("SELECT id, is_admin FROM users WHERE user_name = ?", (username,))
    user = cur.fetchone()
    if not user:
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    if user['is_admin']:
        return {'success': False, 'output': '不能删除管理员账号', 'data': {}}
    
    # 清除好友关系（需在删除用户前执行，子查询依赖 users 表）
    cur.execute("DELETE FROM friends WHERE user_uid IN (SELECT uid FROM users WHERE user_name = ?) OR friend_uid IN (SELECT uid FROM users WHERE user_name = ?)", (username, username))
    # 删除用户
    cur.execute("DELETE FROM users WHERE user_name = ?", (username,))
    # 删除充值请求
    cur.execute("DELETE FROM recharge_requests WHERE user_name = ?", (username,))
    # 删除会话
    cur.execute("DELETE FROM sessions WHERE user_name = ?", (username,))
    conn.commit()
    
    output = f"用户 {username} 已删除"
    return {'success': True, 'output': output, 'data': {'username': username}}
            
            # ==================== 封禁用户 ====================


def _debug_console_cmd_ban_user(conn, cur, args) -> dict:
    if len(args) < 2:
        return {'success': False, 'output': '用法：ban_user <username> <reason> [days]', 'data': {}}
    
    username = args[0]
    reason = args[1]
    days = int(args[2]) if len(args) > 2 else None
    
    cur.execute("SELECT id, is_admin FROM users WHERE user_name = ?", (username,))
    user = cur.fetchone()
    if not user:
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    if user['is_admin']:
        return {'success': False, 'output': '不能封禁管理员', 'data': {}}
    
    import datetime
    expire_at = None
    if days:
        expire_at = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    
    cur.execute(
        "UPDATE users SET is_banned = 1, ban_reason = ?, ban_expire_at = ? WHERE user_name = ?",
        (reason, expire_at, username)
    )
    # 踢掉所有会话
    cur.execute("DELETE FROM sessions WHERE user_name = ?", (username,))
    conn.commit()
    
    expire_str = f"{days} 天后过期" if days else "永久封禁"
    output = f"用户 {username} 已封禁\n原因：{reason}\n有效期：{expire_str}"
    return {'success': True, 'output': output, 'data': {'username': username, 'reason': reason, 'days': days}}
            
            # ==================== 解封用户 ====================


def _debug_console_cmd_unban_user(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：unban_user <username>', 'data': {}}
    
    username = args[0]
    
    cur.execute("SELECT id FROM users WHERE user_name = ?", (username,))
    if not cur.fetchone():
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    cur.execute(
        "UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expire_at = NULL WHERE user_name = ?",
        (username,)
    )
    conn.commit()
    
    output = f"用户 {username} 已解封"
    return {'success': True, 'output': output, 'data': {'username': username}}
            
            # ==================== 设置余额 ====================


def _debug_console_cmd_set_balence(conn, cur, args) -> dict:
    if len(args) < 2:
        return {'success': False, 'output': '用法：set_balence <username> <amount>', 'data': {}}
    
    username = args[0]
    amount = float(args[1])
    
    cur.execute("SELECT id FROM users WHERE user_name = ?", (username,))
    if not cur.fetchone():
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    cur.execute(
        "UPDATE users SET balence = ? WHERE user_name = ?",
        (amount, username)
    )
    conn.commit()
    
    output = f"用户 {username} 余额已设置为 {amount:.6f} 元"
    return {'success': True, 'output': output, 'data': {'username': username, 'balence': amount}}
            
            # ==================== 增加余额 ====================


def _debug_console_cmd_add_balence(conn, cur, args) -> dict:
    if len(args) < 2:
        return {'success': False, 'output': '用法：add_balence <username> <amount>', 'data': {}}
    
    username = args[0]
    amount = float(args[1])
    
    cur.execute("SELECT id, balence FROM users WHERE user_name = ?", (username,))
    user = cur.fetchone()
    if not user:
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    new_balence = user['balence'] + amount
    cur.execute(
        "UPDATE users SET balence = ? WHERE user_name = ?",
        (new_balence, username)
    )
    conn.commit()
    
    output = f"用户 {username} 余额增加 {amount:.6f} 元\n当前余额：{new_balence:.6f} 元"
    return {'success': True, 'output': output, 'data': {'username': username, 'added': amount, 'new_balence': new_balence}}
            
            # ==================== 充值请求列表 ====================


def _debug_console_cmd_list_recharges(conn, cur, args) -> dict:
    status = args[0] if args else 'pending'
    
    cur.execute(
        "SELECT * FROM recharge_requests WHERE status = ? ORDER BY created_at DESC LIMIT 50",
        (status,)
    )
    recharges = cur.fetchall()
    
    if not recharges:
        return {'success': True, 'output': '没有充值请求', 'data': {'recharges': []}}
    
    lines = [f"充值请求（{status}）："]
    for r in recharges:
        lines.append(f"  [{r['request_id']}] {r['user_name']}  金额: {r['amount']} 元  时间: {r['created_at']}")
    
    output = '\n'.join(lines)
    return {'success': True, 'output': output, 'data': {'recharges': [dict(r) for r in recharges]}}
            
            # ==================== 通过充值 ====================


def _debug_console_cmd_approve_recharge(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：approve_recharge <request_id>', 'data': {}}
    
    request_id = args[0]
    
    cur.execute("SELECT * FROM recharge_requests WHERE request_id = ?", (request_id,))
    req = cur.fetchone()
    if not req:
        return {'success': False, 'output': f'充值请求 {request_id} 不存在', 'data': {}}
    
    if req['status'] != 'pending':
        return {'success': False, 'output': f'充值请求状态为 {req["status"]}，无法通过', 'data': {}}
    
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 更新充值状态
    cur.execute(
        "UPDATE recharge_requests SET status = 'approved', processed_at = ? WHERE request_id = ?",
        (now, request_id)
    )
    
    # 增加用户余额
    cur.execute(
        "UPDATE users SET balence = balence + ? WHERE user_name = ?",
        (req['amount'], req['user_name'])
    )
    conn.commit()
    
    output = f"充值请求 {request_id} 已通过\n用户：{req['user_name']}\n金额：{req['amount']} 元"
    return {'success': True, 'output': output, 'data': {'request_id': request_id, 'amount': req['amount'], 'user': req['user_name']}}
            
            # ==================== 拒绝充值 ====================


def _debug_console_cmd_reject_recharge(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：reject_recharge <request_id> [reason]', 'data': {}}
    
    request_id = args[0]
    reason = args[1] if len(args) > 1 else '管理员拒绝'
    
    cur.execute("SELECT * FROM recharge_requests WHERE request_id = ?", (request_id,))
    req = cur.fetchone()
    if not req:
        return {'success': False, 'output': f'充值请求 {request_id} 不存在', 'data': {}}
    
    if req['status'] != 'pending':
        return {'success': False, 'output': f'充值请求状态为 {req["status"]}，无法拒绝', 'data': {}}
    
    import datetime
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cur.execute(
        "UPDATE recharge_requests SET status = 'rejected', admin_remark = ?, processed_at = ? WHERE request_id = ?",
        (reason, now, request_id)
    )
    conn.commit()
    
    output = f"充值请求 {request_id} 已拒绝\n原因：{reason}"
    return {'success': True, 'output': output, 'data': {'request_id': request_id, 'reason': reason}}
            
            # ==================== 查看用户会话 ====================


def _debug_console_cmd_list_sessions(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：list_sessions <username>', 'data': {}}
    
    username = args[0]
    
    cur.execute("""
        SELECT session_id, user_agent, ip_address, created_at, last_active_at, expires_at
        FROM sessions
        WHERE user_name = ? AND expires_at > datetime('now')
        ORDER BY last_active_at DESC
    """, (username,))
    sessions = cur.fetchall()
    
    if not sessions:
        return {'success': True, 'output': f'用户 {username} 没有活跃会话', 'data': {'sessions': []}}
    
    lines = [f"用户 {username} 的活跃会话（{len(sessions)} 个）："]
    for i, s in enumerate(sessions, 1):
        short_id = s['session_id'][:8] + '...'
        lines.append(f"  {i}. [{short_id}] IP: {s['ip_address'] or '未知'}  最后活跃: {s['last_active_at']}")
        if s['user_agent']:
            ua_short = s['user_agent'][:60] + '...' if len(s['user_agent']) > 60 else s['user_agent']
            lines.append(f"     设备: {ua_short}")
    
    output = '\n'.join(lines)
    return {'success': True, 'output': output, 'data': {'sessions': [dict(s) for s in sessions]}}
            
            # ==================== 踢掉指定会话 ====================


def _debug_console_cmd_kick_session(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：kick_session <session_id>', 'data': {}}
    
    session_id = args[0]
    
    cur.execute("SELECT user_name FROM sessions WHERE session_id = ?", (session_id,))
    sess = cur.fetchone()
    if not sess:
        return {'success': False, 'output': f'会话 {session_id} 不存在', 'data': {}}
    
    cur.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    conn.commit()
    
    output = f"会话 {session_id[:8]}... 已踢掉\n用户：{sess['user_name']}"
    return {'success': True, 'output': output, 'data': {'session_id': session_id, 'user': sess['user_name']}}
            
            # ==================== 踢掉用户所有会话 ====================


def _debug_console_cmd_kick_all_sessions(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：kick_all_sessions <username>', 'data': {}}
    
    username = args[0]
    
    cur.execute("SELECT COUNT(*) as cnt FROM sessions WHERE user_name = ?", (username,))
    count = cur.fetchone()['cnt']
    
    cur.execute("DELETE FROM sessions WHERE user_name = ?", (username,))
    conn.commit()
    
    output = f"用户 {username} 的所有 {count} 个会话已踢掉"
    return {'success': True, 'output': output, 'data': {'username': username, 'kicked_count': count}}
            
            # ==================== 清理过期会话 ====================


def _debug_console_cmd_cleanup_sessions(conn, cur, args) -> dict:
    cur.execute("DELETE FROM sessions WHERE expires_at <= datetime('now')")
    count = cur.rowcount
    conn.commit()
    
    output = f"已清理 {count} 个过期会话"
    return {'success': True, 'output': output, 'data': {'cleaned_count': count}}
            
            # ==================== 列出 API Key ====================


def _debug_console_cmd_list_apikeys(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：list_apikeys <username>', 'data': {}}
    
    username = args[0]
    
    cur.execute("SELECT apikeys FROM users WHERE user_name = ?", (username,))
    user = cur.fetchone()
    if not user:
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    apikeys = user['apikeys'].split(',') if user['apikeys'] else []
    apikeys = [k for k in apikeys if k]
    
    if not apikeys:
        return {'success': True, 'output': f'用户 {username} 没有 API Key', 'data': {'apikeys': []}}
    
    lines = [f"用户 {username} 的 API Key（{len(apikeys)} 个）："]
    for i, key in enumerate(apikeys, 1):
        masked = key[:10] + '...' + key[-6:]
        lines.append(f"  {i}. {masked}")
    
    output = '\n'.join(lines)
    return {'success': True, 'output': output, 'data': {'apikeys': apikeys}}
            
            # ==================== 生成 API Key ====================


def _debug_console_cmd_gen_apikey(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：gen_apikey <username>', 'data': {}}
    
    username = args[0]
    
    # 先获取用户信息
    cur.execute("SELECT * FROM users WHERE user_name = ?", (username,))
    user = cur.fetchone()
    if not user:
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    # 导入 apikey 模块的函数
    try:
        from .apikey import _gen_and_save_apikey
        new_key = _gen_and_save_apikey(username, dict(user))
        output = f"API Key 生成成功：{new_key}"
        return {'success': True, 'output': output, 'data': {'apikey': new_key}}
    except Exception as e:
        return {'success': False, 'output': f'生成失败：{str(e)}', 'data': {}}
            
            # ==================== 吊销 API Key ====================


def _debug_console_cmd_revoke_apikey(conn, cur, args) -> dict:
    if len(args) < 2:
        return {'success': False, 'output': '用法：revoke_apikey <username> <apikey>', 'data': {}}
    
    username = args[0]
    apikey = args[1]
    
    cur.execute("SELECT apikeys FROM users WHERE user_name = ?", (username,))
    user = cur.fetchone()
    if not user:
        return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
    
    apikeys = user['apikeys'].split(',') if user['apikeys'] else []
    if apikey not in apikeys:
        return {'success': False, 'output': 'API Key 不存在', 'data': {}}
    
    apikeys.remove(apikey)
    new_apikeys = ','.join(apikeys)
    
    cur.execute(
        "UPDATE users SET apikeys = ? WHERE user_name = ?",
        (new_apikeys, username)
    )
    conn.commit()
    
    output = f"API Key 已吊销：{apikey[:10]}..."
    return {'success': True, 'output': output, 'data': {'apikey': apikey}}
            
            # ==================== 列出 Debug Console 密钥 ====================


def _debug_console_cmd_list_debug_console_keys(conn, cur, args) -> dict:
    cur.execute("""
        SELECT id, key_name, created_at, last_used_at, last_used_ip, is_active
        FROM debug_console_keys ORDER BY created_at DESC
    """)
    keys = cur.fetchall()
    
    if not keys:
        return {'success': True, 'output': '没有 Debug Console 密钥', 'data': {'keys': []}}
    
    lines = [f"Debug Console 密钥列表（{len(keys)} 个）："]
    for k in keys:
        status = '活跃' if k['is_active'] else '已撤销'
        lines.append(f"  [{k['id']}] {k['key_name']}  状态: {status}  创建: {k['created_at']}")
        if k['last_used_at']:
            lines.append(f"      最后使用: {k['last_used_at']}  IP: {k['last_used_ip'] or '未知'}")
    
    output = '\n'.join(lines)
    return {'success': True, 'output': output, 'data': {'keys': [dict(k) for k in keys]}}
            
            # ==================== 生成 Debug Console 密钥 ====================


def _debug_console_cmd_gen_debug_console_key(conn, cur, args) -> dict:
    key_name = args[0] if args else 'default'
    
    import os
    import base64
    import hashlib
    
    key_bytes = os.urandom(16)
    key_b64 = base64.b64encode(key_bytes).decode('ascii')
    key_hash = hashlib.sha256(key_b64.encode('utf-8')).hexdigest()
    
    cur.execute(
        "INSERT INTO debug_console_keys (key_hash, key_name) VALUES (?, ?)",
        (key_hash, key_name)
    )
    conn.commit()
    
    output = f"新 Debug Console 密钥生成成功（只显示一次）：\n{key_b64}\n名称：{key_name}"
    return {'success': True, 'output': output, 'data': {'key': key_b64, 'name': key_name}}
            
            # ==================== 撤销 Debug Console 密钥 ====================


def _debug_console_cmd_revoke_debug_console_key(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：revoke_debug_console_key <id>', 'data': {}}
    
    key_id = int(args[0])
    
    cur.execute("SELECT key_name FROM debug_console_keys WHERE id = ?", (key_id,))
    key = cur.fetchone()
    if not key:
        return {'success': False, 'output': f'Debug Console 密钥 {key_id} 不存在', 'data': {}}
    
    cur.execute("UPDATE debug_console_keys SET is_active = 0 WHERE id = ?", (key_id,))
    conn.commit()
    
    output = f"Debug Console 密钥 [{key_id}] {key['key_name']} 已撤销"
    return {'success': True, 'output': output, 'data': {'key_id': key_id, 'name': key['key_name']}}
            
            # ==================== IP 白名单（仅 Debug Console 可控制） ====================


def _debug_console_cmd_whitelist(conn, cur, args) -> dict:
    if not args:
        return {'success': False, 'output': '用法：whitelist <add|remove|list|check> <ip> [note] [bypass]', 'data': {}}
    sub = args[0]
    if sub == 'add':
        if len(args) < 2:
            return {'success': False, 'output': '用法：whitelist add <ip> [note] [bypass]', 'data': {}}
        wip = args[1].strip()
        note = args[2] if len(args) > 2 else ''
        bypass = args[3].strip().lower() if len(args) > 3 else 'all'
        valid = {'all', 'blacklist', 'autoban', 'account_ban', 'ratelimit', 'device_ban'}
        if bypass != 'all':
            for p in bypass.split(','):
                if p.strip() not in valid:
                    return {'success': False, 'output': f'无效的 bypass 类别：{p.strip()}', 'data': {}}
        import re as _re
        if not _re.match(r'^[0-9a-fA-F:.]+(/\d+)?$', wip):
            return {'success': False, 'output': '无效的 IP / CIDR 格式', 'data': {}}
        try:
            cur.execute(
                "INSERT OR REPLACE INTO ip_whitelist (ip, note, bypass) VALUES (?, ?, ?)",
                (wip, note, bypass)
            )
            conn.commit()
        except Exception as e:
            return {'success': False, 'output': f'数据库错误：{e}', 'data': {}}
        output = f"已加入白名单：{wip}  绕过范围: {bypass}" + (f"  备注: {note}" if note else "")
        return {'success': True, 'output': output, 'data': {'ip': wip, 'bypass': bypass}}
    elif sub == 'remove':
        if len(args) < 2:
            return {'success': False, 'output': '用法：whitelist remove <ip>', 'data': {}}
        wip = args[1].strip()
        cur.execute("DELETE FROM ip_whitelist WHERE ip = ?", (wip,))
        conn.commit()
        return {'success': True, 'output': f'已从白名单移除：{wip}', 'data': {'ip': wip}}
    elif sub == 'list':
        cur.execute("SELECT id, ip, note, bypass, created_at FROM ip_whitelist ORDER BY id DESC")
        rows = cur.fetchall()
        if not rows:
            return {'success': True, 'output': '白名单为空', 'data': {'whitelist': []}}
        lines = [f"IP 白名单（{len(rows)} 条）："]
        for r in rows:
            lines.append(f"  [{r['id']}] {r['ip']}  绕过: {r['bypass']}  备注: {r['note'] or '-'}  添加: {r['created_at']}")
        return {'success': True, 'output': '\n'.join(lines), 'data': {'whitelist': [dict(r) for r in rows]}}
    elif sub == 'check':
        if len(args) < 2:
            return {'success': False, 'output': '用法：whitelist check <ip>', 'data': {}}
        wip = args[1].strip()
        cur.execute("SELECT ip, note, bypass FROM ip_whitelist")
        rows = cur.fetchall()
        hit = None
        for r in rows:
            if _ip_in_cidr(wip, r['ip']):
                hit = dict(r)
                break
        if hit:
            return {'success': True, 'output': f'{wip} 命中白名单：{hit["ip"]} 绕过: {hit["bypass"]}', 'data': {'match': hit}}
        return {'success': True, 'output': f'{wip} 不在白名单中', 'data': {'match': None}}
    else:
        return {'success': False, 'output': f'未知子命令：{sub}（支持 add/remove/list/check）', 'data': {}}
            
            # ==================== 未知命令 ====================


_DEBUG_CONSOLE_HANDLERS = {
    'help': _debug_console_cmd_help,
    'status': _debug_console_cmd_status,
    'stats': _debug_console_cmd_stats,
    'list_users': _debug_console_cmd_list_users,
    'get_user': _debug_console_cmd_get_user,
    'create_user': _debug_console_cmd_create_user,
    'delete_user': _debug_console_cmd_delete_user,
    'ban_user': _debug_console_cmd_ban_user,
    'unban_user': _debug_console_cmd_unban_user,
    'set_balence': _debug_console_cmd_set_balence,
    'add_balence': _debug_console_cmd_add_balence,
    'list_recharges': _debug_console_cmd_list_recharges,
    'approve_recharge': _debug_console_cmd_approve_recharge,
    'reject_recharge': _debug_console_cmd_reject_recharge,
    'list_sessions': _debug_console_cmd_list_sessions,
    'kick_session': _debug_console_cmd_kick_session,
    'kick_all_sessions': _debug_console_cmd_kick_all_sessions,
    'cleanup_sessions': _debug_console_cmd_cleanup_sessions,
    'list_apikeys': _debug_console_cmd_list_apikeys,
    'gen_apikey': _debug_console_cmd_gen_apikey,
    'revoke_apikey': _debug_console_cmd_revoke_apikey,
    'list_debug_console_keys': _debug_console_cmd_list_debug_console_keys,
    'gen_debug_console_key': _debug_console_cmd_gen_debug_console_key,
    'revoke_debug_console_key': _debug_console_cmd_revoke_debug_console_key,
    'whitelist': _debug_console_cmd_whitelist,
}

def _execute_debug_console_command_sync(command: str, args: list = None) -> dict:
    """执行 Debug Console 命令（同步版本）。命令分发到独立 handler。

    Returns:
        {success: bool, output: str, data: dict}
    """
    if args is None:
        args = []

    handler = _DEBUG_CONSOLE_HANDLERS.get(command)
    if handler is None:
        return {'success': False, 'output': f'未知命令：{command}\n输入 help 查看可用命令', 'data': {}}

    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            return handler(conn, cur, args)
    except Exception as e:
        return {'success': False, 'output': f'执行出错：{str(e)}', 'data': {'error': str(e)}}

# 异步版本
async def _generate_debug_console_key(key_name: str = "default") -> str:
    import asyncio
    return await asyncio.to_thread(_generate_debug_console_key_sync, key_name)

async def _validate_debug_console_key(key_b64: str, ip: str = "") -> bool:
    import asyncio
    return await asyncio.to_thread(_validate_debug_console_key_sync, key_b64, ip)

async def _list_debug_console_keys() -> list:
    import asyncio
    return await asyncio.to_thread(_list_debug_console_keys_sync)

async def _revoke_debug_console_key(key_id: int) -> bool:
    import asyncio
    return await asyncio.to_thread(_revoke_debug_console_key_sync, key_id)

async def _execute_debug_console_command(command: str, args: list = None) -> dict:
    import asyncio
    return await asyncio.to_thread(_execute_debug_console_command_sync, command, args)
async def _debug_console_auth():
    """验证 Debug Console 密钥，返回 (is_valid: bool, error_response: tuple | None)

    注意：_verify_debug_console_key 为协程函数，必须 await。
    历史缺陷：此处曾同步调用，得到的 coroutine 对象恒为真值，
    导致 `not _verify_debug_console_key(key)` 永远为 False，Debug Console 鉴权被完全绕过。
    """
    key = request.headers.get('X-Debug-Console-Key', '')
    if not await _verify_debug_console_key(key):
        return False, (jsonify({'error': 'Invalid Debug Console key'}), 403)
    return True, None


def _start_debug_console_server_thread():
    """在独立线程中启动 Debug Console 服务器"""
    import threading
    
    def run_debug_console():
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            from .debug_console import start_debug_console_server
            server = loop.run_until_complete(start_debug_console_server())
            loop.run_until_complete(server.serve_forever())
        except Exception as e:
            logging.error(f"Debug Console server error: {e}")
    
    thread = threading.Thread(target=run_debug_console, daemon=True, name='Debug Console-Server')
    thread.start()
    return thread
def _is_debug_console_authenticated() -> bool:
    """检查 Debug Console Web 是否已通过双重认证（独立 session，不与普通用户混用）"""
    return session.get('debug_console_authenticated', False)


async def _debug_console_verify_admin_credentials(username: str, password: str) -> bool:
    """验证管理员账号密码（用于 Debug Console Web 双重认证）"""
    if not username or not password:
        return False
    
    try:
        user = await _get_user_by_name(username)
        if not user:
            return False
        
        # 检查是否是管理员
        if not user.get('is_admin', 0):
            return False
        
        # 验证密码
        return verify_password(password, user['user_password'])
    except Exception:
        return False
