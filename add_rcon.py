import sys

with open('__main__.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 找到插入位置
old = """async def _cleanup_expired_sessions():
    \"\"\"清理所有过期会话（异步版本）\"\"\"
    import asyncio
    return await asyncio.to_thread(_cleanup_expired_sessions_sync)


def _bufpay_sign(params: dict) -> str:"""

# BufPay 已清理：改用稳定锚点，并在 RCON 已集成时跳过
anchor = "# ---------- RCON 远程控制台 API（最高权限，类似 SYSTEM/root）"
if "def _rcon_auth" in content:
    print("RCON already integrated, nothing to do.")
    sys.exit(0)
if anchor not in content:
    print("ERROR: Could not find RCON anchor")
    sys.exit(1)

# 读取 RCON 代码
rcon_code = '''
# ---------- RCON 远程控制台 ----------

def _generate_rcon_key_sync(key_name: str = "default") -> str:
    """生成新的 RCON 密钥（同步版本）
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
            "INSERT INTO rcon_keys (key_hash, key_name) VALUES (?, ?)",
            (key_hash, key_name)
        )
        conn.commit()
    
    return key_b64


def _validate_rcon_key_sync(key_b64: str, ip: str = "") -> bool:
    """验证 RCON 密钥是否有效（同步版本）"""
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
            "SELECT id FROM rcon_keys WHERE key_hash = ? AND is_active = 1",
            (key_hash,)
        )
        row = cur.fetchone()
        
        if row:
            # 更新最后使用时间
            cur.execute(
                "UPDATE rcon_keys SET last_used_at = ?, last_used_ip = ? WHERE key_hash = ?",
                (now, ip, key_hash)
            )
            conn.commit()
            return True
    
    return False


def _list_rcon_keys_sync() -> list:
    """列出所有 RCON 密钥（同步版本，不返回明文）"""
    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, key_name, created_at, last_used_at, last_used_ip, is_active
            FROM rcon_keys ORDER BY created_at DESC
        """)
        rows = cur.fetchall()
        return [dict(row) for row in rows]


def _revoke_rcon_key_sync(key_id: int) -> bool:
    """撤销 RCON 密钥（同步版本）"""
    conn = _get_conn()
    with conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE rcon_keys SET is_active = 0 WHERE id = ?",
            (key_id,)
        )
        conn.commit()
        return cur.rowcount > 0


def _execute_rcon_command_sync(command: str, args: list = None) -> dict:
    """执行 RCON 命令（同步版本）
    Returns:
        {success: bool, output: str, data: dict}
    """
    if args is None:
        args = []
    
    conn = _get_conn()
    
    try:
        with conn:
            cur = conn.cursor()
            
            # ==================== 帮助 ====================
            if command == 'help':
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

  RCON 密钥管理：
    list_rcon_keys               列出 RCON 密钥
    gen_rcon_key [name]          生成新 RCON 密钥
    revoke_rcon_key <id>         撤销 RCON 密钥"""
                return {'success': True, 'output': output, 'data': {}}
            
            # ==================== 状态 ====================
            elif command == 'status':
                cur.execute("SELECT COUNT(*) as cnt FROM users")
                user_count = cur.fetchone()['cnt']
                cur.execute("SELECT COUNT(*) as cnt FROM sessions WHERE expires_at > datetime('now')")
                session_count = cur.fetchone()['cnt']
                cur.execute("SELECT COUNT(*) as cnt FROM recharge_requests WHERE status = 'pending'")
                pending_recharges = cur.fetchone()['cnt']
                cur.execute("SELECT COUNT(*) as cnt FROM rcon_keys WHERE is_active = 1")
                rcon_keys = cur.fetchone()['cnt']
                
                output = f"""服务器状态：运行中
用户总数：{user_count}
活跃会话：{session_count}
待处理充值：{pending_recharges}
活跃 RCON 密钥：{rcon_keys}"""
                return {'success': True, 'output': output, 'data': {
                    'user_count': user_count,
                    'session_count': session_count,
                    'pending_recharges': pending_recharges,
                    'rcon_keys': rcon_keys
                }}
            
            # ==================== 统计 ====================
            elif command == 'stats':
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
            elif command == 'list_users':
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
                
                output = '\\n'.join(lines)
                return {'success': True, 'output': output, 'data': {'users': [dict(u) for u in users], 'total': total, 'page': page}}
            
            # ==================== 获取用户信息 ====================
            elif command == 'get_user':
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
            elif command == 'create_user':
                if len(args) < 2:
                    return {'success': False, 'output': '用法：create_user <username> <password> [balence]', 'data': {}}
                
                username = args[0]
                password = args[1]
                balence = float(args[2]) if len(args) > 2 else 0.0
                
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
                
                output = f"用户 {username} 创建成功\\nUID: {uid}\\n初始余额：{balence:.6f} 元"
                return {'success': True, 'output': output, 'data': {'username': username, 'uid': uid, 'balence': balence}}
            
            # ==================== 删除用户 ====================
            elif command == 'delete_user':
                if not args:
                    return {'success': False, 'output': '用法：delete_user <username>', 'data': {}}
                
                username = args[0]
                
                cur.execute("SELECT id, is_admin FROM users WHERE user_name = ?", (username,))
                user = cur.fetchone()
                if not user:
                    return {'success': False, 'output': f'用户 {username} 不存在', 'data': {}}
                
                if user['is_admin']:
                    return {'success': False, 'output': '不能删除管理员账号', 'data': {}}
                
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
            elif command == 'ban_user':
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
                output = f"用户 {username} 已封禁\\n原因：{reason}\\n有效期：{expire_str}"
                return {'success': True, 'output': output, 'data': {'username': username, 'reason': reason, 'days': days}}
            
            # ==================== 解封用户 ====================
            elif command == 'unban_user':
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
            elif command == 'set_balence':
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
            elif command == 'add_balence':
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
                
                output = f"用户 {username} 余额增加 {amount:.6f} 元\\n当前余额：{new_balence:.6f} 元"
                return {'success': True, 'output': output, 'data': {'username': username, 'added': amount, 'new_balence': new_balence}}
            
            # ==================== 充值请求列表 ====================
            elif command == 'list_recharges':
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
                
                output = '\\n'.join(lines)
                return {'success': True, 'output': output, 'data': {'recharges': [dict(r) for r in recharges]}}
            
            # ==================== 通过充值 ====================
            elif command == 'approve_recharge':
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
                
                output = f"充值请求 {request_id} 已通过\\n用户：{req['user_name']}\\n金额：{req['amount']} 元"
                return {'success': True, 'output': output, 'data': {'request_id': request_id, 'amount': req['amount'], 'user': req['user_name']}}
            
            # ==================== 拒绝充值 ====================
            elif command == 'reject_recharge':
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
                
                output = f"充值请求 {request_id} 已拒绝\\n原因：{reason}"
                return {'success': True, 'output': output, 'data': {'request_id': request_id, 'reason': reason}}
            
            # ==================== 查看用户会话 ====================
            elif command == 'list_sessions':
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
                
                output = '\\n'.join(lines)
                return {'success': True, 'output': output, 'data': {'sessions': [dict(s) for s in sessions]}}
            
            # ==================== 踢掉指定会话 ====================
            elif command == 'kick_session':
                if not args:
                    return {'success': False, 'output': '用法：kick_session <session_id>', 'data': {}}
                
                session_id = args[0]
                
                cur.execute("SELECT user_name FROM sessions WHERE session_id = ?", (session_id,))
                sess = cur.fetchone()
                if not sess:
                    return {'success': False, 'output': f'会话 {session_id} 不存在', 'data': {}}
                
                cur.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
                
                output = f"会话 {session_id[:8]}... 已踢掉\\n用户：{sess['user_name']}"
                return {'success': True, 'output': output, 'data': {'session_id': session_id, 'user': sess['user_name']}}
            
            # ==================== 踢掉用户所有会话 ====================
            elif command == 'kick_all_sessions':
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
            elif command == 'cleanup_sessions':
                cur.execute("DELETE FROM sessions WHERE expires_at <= datetime('now')")
                count = cur.rowcount
                conn.commit()
                
                output = f"已清理 {count} 个过期会话"
                return {'success': True, 'output': output, 'data': {'cleaned_count': count}}
            
            # ==================== 列出 API Key ====================
            elif command == 'list_apikeys':
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
                
                output = '\\n'.join(lines)
                return {'success': True, 'output': output, 'data': {'apikeys': apikeys}}
            
            # ==================== 生成 API Key ====================
            elif command == 'gen_apikey':
                if not args:
                    return {'success': False, 'output': '用法：gen_apikey <username>', 'data': {}}
                
                username = args[0]
                
                # 导入 apikey 模块的函数
                try:
                    from .apikey import _gen_and_save_apikey
                    new_key = _gen_and_save_apikey(username)
                    output = f"API Key 生成成功：{new_key}"
                    return {'success': True, 'output': output, 'data': {'apikey': new_key}}
                except Exception as e:
                    return {'success': False, 'output': f'生成失败：{str(e)}', 'data': {}}
            
            # ==================== 吊销 API Key ====================
            elif command == 'revoke_apikey':
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
            
            # ==================== 列出 RCON 密钥 ====================
            elif command == 'list_rcon_keys':
                cur.execute("""
                    SELECT id, key_name, created_at, last_used_at, last_used_ip, is_active
                    FROM rcon_keys ORDER BY created_at DESC
                """)
                keys = cur.fetchall()
                
                if not keys:
                    return {'success': True, 'output': '没有 RCON 密钥', 'data': {'keys': []}}
                
                lines = [f"RCON 密钥列表（{len(keys)} 个）："]
                for k in keys:
                    status = '活跃' if k['is_active'] else '已撤销'
                    lines.append(f"  [{k['id']}] {k['key_name']}  状态: {status}  创建: {k['created_at']}")
                    if k['last_used_at']:
                        lines.append(f"      最后使用: {k['last_used_at']}  IP: {k['last_used_ip'] or '未知'}")
                
                output = '\\n'.join(lines)
                return {'success': True, 'output': output, 'data': {'keys': [dict(k) for k in keys]}}
            
            # ==================== 生成 RCON 密钥 ====================
            elif command == 'gen_rcon_key':
                key_name = args[0] if args else 'default'
                
                import os
                import base64
                import hashlib
                
                key_bytes = os.urandom(16)
                key_b64 = base64.b64encode(key_bytes).decode('ascii')
                key_hash = hashlib.sha256(key_b64.encode('utf-8')).hexdigest()
                
                cur.execute(
                    "INSERT INTO rcon_keys (key_hash, key_name) VALUES (?, ?)",
                    (key_hash, key_name)
                )
                conn.commit()
                
                output = f"新 RCON 密钥生成成功（只显示一次）：\\n{key_b64}\\n名称：{key_name}"
                return {'success': True, 'output': output, 'data': {'key': key_b64, 'name': key_name}}
            
            # ==================== 撤销 RCON 密钥 ====================
            elif command == 'revoke_rcon_key':
                if not args:
                    return {'success': False, 'output': '用法：revoke_rcon_key <id>', 'data': {}}
                
                key_id = int(args[0])
                
                cur.execute("SELECT key_name FROM rcon_keys WHERE id = ?", (key_id,))
                key = cur.fetchone()
                if not key:
                    return {'success': False, 'output': f'RCON 密钥 {key_id} 不存在', 'data': {}}
                
                cur.execute("UPDATE rcon_keys SET is_active = 0 WHERE id = ?", (key_id,))
                conn.commit()
                
                output = f"RCON 密钥 [{key_id}] {key['key_name']} 已撤销"
                return {'success': True, 'output': output, 'data': {'key_id': key_id, 'name': key['key_name']}}
            
            # ==================== 未知命令 ====================
            else:
                return {'success': False, 'output': f'未知命令：{command}\\n输入 help 查看可用命令', 'data': {}}
    
    except Exception as e:
        return {'success': False, 'output': f'执行出错：{str(e)}', 'data': {'error': str(e)}}


# 异步版本
async def _generate_rcon_key(key_name: str = "default") -> str:
    import asyncio
    return await asyncio.to_thread(_generate_rcon_key_sync, key_name)

async def _validate_rcon_key(key_b64: str, ip: str = "") -> bool:
    import asyncio
    return await asyncio.to_thread(_validate_rcon_key_sync, key_b64, ip)

async def _list_rcon_keys() -> list:
    import asyncio
    return await asyncio.to_thread(_list_rcon_keys_sync)

async def _revoke_rcon_key(key_id: int) -> bool:
    import asyncio
    return await asyncio.to_thread(_revoke_rcon_key_sync, key_id)

async def _execute_rcon_command(command: str, args: list = None) -> dict:
    import asyncio
    return await asyncio.to_thread(_execute_rcon_command_sync, command, args)

'''

# 插入
content = content.replace(old, rcon_code + '\n' + old.split('\n')[-1])

# 等等，不对，old 包含两行，我需要更精确的处理
# 重新来：找到 old 的位置，然后在 _bufpay_sign 之前插入

# 在 RCON 锚点前插入 RCON 代码（仅在未集成时进入此分支）
content = content.replace(anchor, rcon_code + "\n" + anchor, 1)

with open('__main__.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("SUCCESS: Added RCON functions")
