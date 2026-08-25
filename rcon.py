"""
RCON 远程控制台模块
最高权限级别，相当于 SYSTEM/root
使用 TLS 1.3 加密传输，密钥认证
"""

import asyncio
import ssl
import os
import base64
import json
import logging
import datetime
import sqlite3
from pathlib import Path

# 配置
RCON_PORT = 5001
RCON_KEY_LENGTH = 16  # 128位 = 16字节
# 数据库路径必须与主应用一致：历史实现在此硬编码 users.db，忽略了 DB_PATH
# 配置项/环境变量，一旦部署自定义数据库位置，TCP RCON 服务就会连到另一个库。
# configs.py 只依赖标准库，此处导入不会引入循环依赖。
try:
    from .configs import DB_PATH
except Exception:  # 允许脱离包上下文单文件运行
    DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')
CERT_DIR = os.path.join(os.path.dirname(__file__), 'certs')


def _get_conn():
    """获取数据库连接（SQLite / PostgreSQL，经 db 抽象层统一）"""
    from . import db
    return db.get_conn()

def _get_user_by_identifier(identifier: str) -> dict | None:
    """通过用户名或 UID 查找用户
    自动检测标识符类型：12位十六进制视为 UID，否则视为用户名
    """
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            # 先尝试按 UID 查找（12位十六进制）
            if len(identifier) == 12 and all(c in '0123456789abcdef' for c in identifier.lower()):
                cur.execute("SELECT * FROM users WHERE uid = ?", (identifier,))
                user = cur.fetchone()
                if user:
                    return dict(user)
            # 再按用户名查找
            cur.execute("SELECT * FROM users WHERE user_name = ?", (identifier,))
            user = cur.fetchone()
            return dict(user) if user else None
    finally:
        conn.close()


def _ensure_config_table():
    """确保 system_config 表存在"""
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS system_config (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    finally:
        conn.close()


def _get_config(key: str, default=None) -> str | None:
    """获取系统配置"""
    _ensure_config_table()
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM system_config WHERE key = ?", (key,))
            row = cur.fetchone()
            return row['value'] if row else default
    finally:
        conn.close()


def _set_config(key: str, value: str):
    """设置系统配置"""
    _ensure_config_table()
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO system_config (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
            """, (key, value))
            conn.commit()
    finally:
        conn.close()


def generate_rcon_key() -> str:
    """生成 RCON 密钥（128位，base64编码）"""
    key_bytes = os.urandom(RCON_KEY_LENGTH)
    key_b64 = base64.b64encode(key_bytes).decode('ascii')
    _set_config('rcon_key', key_b64)
    logging.info(f"RCON key regenerated")
    return key_b64


def get_rcon_key() -> str:
    """获取 RCON 密钥，如果不存在则生成"""
    key = _get_config('rcon_key')
    if not key:
        key = generate_rcon_key()
    return key


def generate_tls_cert():
    """生成自签名 TLS 证书"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    os.makedirs(CERT_DIR, exist_ok=True)
    
    cert_path = os.path.join(CERT_DIR, 'rcon_cert.pem')
    key_path = os.path.join(CERT_DIR, 'rcon_key.pem')
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    
    # 生成私钥
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # 生成证书
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "rcon.local"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    
    # 写入证书
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # 写入私钥
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    
    logging.info("TLS certificate generated for RCON")
    return cert_path, key_path


def create_ssl_context() -> ssl.SSLContext:
    """创建 TLS 1.3 上下文"""
    cert_path, key_path = generate_tls_cert()
    
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    
    return ctx


# ========== RCON 命令处理 ==========

class RCONCommandHandler:
    """RCON 命令处理器（最高权限）"""
    
    def __init__(self):
        self.commands = {
            'help': self.cmd_help,
            'status': self.cmd_status,
            'stats': self.cmd_stats,
            'user': self.cmd_user,
            'session': self.cmd_session,
            'key': self.cmd_key,
            'cleanup': self.cmd_cleanup,
            'exit': self.cmd_exit,
            'quit': self.cmd_exit,
        }
    
    async def handle(self, command: str) -> str:
        """处理命令"""
        if not command.strip():
            return ""
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        handler = self.commands.get(cmd)
        if not handler:
            return f"Unknown command: {cmd}\nType 'help' for available commands.\n"
        
        try:
            result = await handler(args)
            return result
        except Exception as e:
            return f"Error: {str(e)}\n"
    
    async def cmd_help(self, args) -> str:
        """显示帮助"""
        help_text = """
RCON 远程控制台 - 最高权限 (SYSTEM/root)

可用命令:
  help                    显示此帮助
  status                  查看服务器状态
  stats                   查看统计信息
  user list               列出所有用户
  user info <user|uid>    查看用户详细信息（支持用户名或UID）
  user create <user> <pass>  创建用户
  user delete <user|uid>  删除用户（支持用户名或UID）
  user password <user|uid> <pass> 修改用户密码（支持用户名或UID）
  user email <user|uid> <email>  设置/修改用户邮箱（支持用户名或UID）
  user admin <user|uid> <0|1> 设置/取消管理员（支持用户名或UID）
  user balence <user|uid> <amount>  调整余额（可正可负，支持用户名或UID）
  user overdraft <user|uid> <amount>  设置超支限额（默认0，不允许超支）
  user ban <user|uid> [reason]     封禁用户（支持用户名或UID）
  user unban <user|uid>            解封用户（支持用户名或UID）
  user clear <user|uid> [types]    清除用户数据（apikeys,sessions,posts,friends,messages,transactions）
  session list <user|uid>      查看用户活跃会话（支持用户名或UID）
  session kick <session_id>    踢掉指定会话
  session kickall <user|uid>   踢掉用户所有会话（支持用户名或UID）
  key refresh             刷新 RSA 密钥对（RSA-2048 + AES-256-GCM 混合加密）
  cleanup                 清理过期会话
  exit / quit             退出连接

示例:
  user list
  user create testuser password123
  user info abc123def456
  user balence testuser 100.0
  user email testuser test@example.com
  user clear testuser apikeys,sessions
  user ban testuser "违规操作"
"""
        return help_text
    
    async def cmd_status(self, args) -> str:
        """查看服务器状态"""
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) as cnt FROM users")
                user_count = cur.fetchone()['cnt']
                
                cur.execute("SELECT COUNT(*) as cnt FROM sessions WHERE expires_at > datetime('now')")
                session_count = cur.fetchone()['cnt']
                
                cur.execute("SELECT COUNT(*) as cnt FROM recharge_requests WHERE status = 'pending'")
                pending_recharge = cur.fetchone()['cnt']
        finally:
            conn.close()
        
        rcon_key = get_rcon_key()
        
        status = f"""
服务器状态
==========
用户总数:     {user_count}
活跃会话:     {session_count}
待审核充值:   {pending_recharge}
RCON 端口:    {RCON_PORT}
RCON 密钥:    {rcon_key}
TLS 版本:     TLS 1.3
"""
        return status
    
    async def cmd_stats(self, args) -> str:
        """查看统计信息"""
        return await self.cmd_status(args)
    
    async def cmd_user(self, args) -> str:
        """用户管理"""
        if not args:
            return "Usage: user <list|info|create|delete|password|email|admin|balence|overdraft|ban|unban|clear> ...\n"
        
        subcmd = args[0].lower()
        
        if subcmd == 'list':
            return await self._user_list()
        elif subcmd == 'info':
            if len(args) < 2:
                return "Usage: user info <user|uid>\n"
            return await self._user_info(args[1])
        elif subcmd == 'create':
            if len(args) < 3:
                return "Usage: user create <username> <password>\n"
            return await self._user_create(args[1], args[2])
        elif subcmd == 'delete':
            if len(args) < 2:
                return "Usage: user delete <user|uid>\n"
            return await self._user_delete(args[1])
        elif subcmd == 'password':
            if len(args) < 3:
                return "Usage: user password <user|uid> <newpassword>\n"
            return await self._user_password(args[1], args[2])
        elif subcmd == 'email':
            if len(args) < 3:
                return "Usage: user email <user|uid> <email>\n"
            return await self._user_email(args[1], args[2])
        elif subcmd == 'admin':
            if len(args) < 3:
                return "Usage: user admin <user|uid> <0|1>\n"
            return await self._user_admin(args[1], args[2])
        elif subcmd == 'balence':
            if len(args) < 3:
                return "Usage: user balence <user|uid> <amount>\n"
            return await self._user_balence(args[1], args[2])
        elif subcmd == 'overdraft':
            if len(args) < 3:
                return "Usage: user overdraft <user|uid> <amount>\n"
            return await self._user_overdraft(args[1], args[2])
        elif subcmd == 'ban':
            if len(args) < 2:
                return "Usage: user ban <user|uid> [reason]\n"
            reason = ' '.join(args[2:]) if len(args) > 2 else '违反服务条款'
            return await self._user_ban(args[1], reason)
        elif subcmd == 'unban':
            if len(args) < 2:
                return "Usage: user unban <user|uid>\n"
            return await self._user_unban(args[1])
        elif subcmd == 'clear':
            if len(args) < 2:
                return "Usage: user clear <user|uid> [types]\n  types: apikeys,sessions,posts,friends,messages,transactions (默认: apikeys,sessions)\n"
            types = args[2] if len(args) > 2 else 'apikeys,sessions'
            return await self._user_clear(args[1], types)
        else:
            return f"Unknown user subcommand: {subcmd}\n"
    
    async def _user_list(self) -> str:
        """列出所有用户"""
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT user_name, uid, is_admin, is_banned, balence, email, created_at
                    FROM users ORDER BY created_at DESC
                """)
                rows = cur.fetchall()
        finally:
            conn.close()
        
        if not rows:
            return "No users found.\n"
        
        lines = ["用户列表", "=" * 80]
        lines.append(f"{'用户名':<20} {'UID':<14} {'角色':<8} {'状态':<8} {'余额':>10} {'邮箱':<20}")
        lines.append("-" * 80)
        
        for row in rows:
            role = 'admin' if row['is_admin'] else 'user'
            status = 'banned' if row['is_banned'] else 'active'
            email = row['email'] or '-'
            balence = f"{row['balence']:.4f}"
            lines.append(f"{row['user_name']:<20} {row['uid']:<14} {role:<8} {status:<8} {balence:>10} {email:<20}")
        
        lines.append(f"\n共 {len(rows)} 个用户")
        return '\n'.join(lines) + '\n'
    
    async def _user_info(self, identifier: str) -> str:
        """查看用户详细信息（支持用户名或UID）"""
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                
                # 活跃会话数
                cur.execute("""
                    SELECT COUNT(*) as cnt FROM sessions 
                    WHERE user_name = ? AND expires_at > datetime('now')
                """, (username,))
                session_count = cur.fetchone()['cnt']
                
                # API Key 数量
                apikeys = user['apikeys'] or ''
                apikey_count = len([k for k in apikeys.split(',') if k])
        finally:
            conn.close()
        
        lines = [f"用户信息: {username}", "=" * 50]
        lines.append(f"UID:            {user['uid']}")
        lines.append(f"角色:           {'管理员' if user['is_admin'] else '普通用户'}")
        lines.append(f"状态:           {'已封禁' if user['is_banned'] else '正常'}")
        if user['is_banned']:
            lines.append(f"封禁原因:       {user['ban_reason'] or '-'}")
        lines.append(f"余额:           {user['balence']:.6f} 元")
        lines.append(f"超支限额:       {user.get('max_overdraft', 0) or 0:.6f} 元")
        lines.append(f"邮箱:           {user['email'] or '-'}")
        lines.append(f"API Key 数量:   {apikey_count}")
        lines.append(f"活跃会话数:     {session_count}")
        lines.append(f"注册时间:       {user['created_at']}")
        lines.append(f"最后登录IP:     {user['last_login_ip'] or '-'}")
        lines.append(f"最后登录时间:   {user['last_login_time'] or '-'}")
        lines.append(f"最大设备数:     {user['max_sessions'] if user['max_sessions'] else 1}")
        
        return '\n'.join(lines) + '\n'
    
    async def _user_create(self, username: str, password: str) -> str:
        """创建用户"""
        import bcrypt
        
        # 密码强度检查
        if len(password) < 6:
            return "Error: Password too short (min 6 chars)\n"
        if not any(c.isalpha() for c in password):
            return "Error: Password must contain at least one letter\n"
        if not any(c.isdigit() for c in password):
            return "Error: Password must contain at least one digit\n"
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                
                # 检查用户名是否存在
                cur.execute("SELECT id FROM users WHERE user_name = ?", (username,))
                if cur.fetchone():
                    return f"Error: Username already exists: {username}\n"
                
                # 生成 UID
                import uuid
                uid = uuid.uuid4().hex[:12]
                
                # 哈希密码
                if len(password.encode('utf-8')) > 72:
                    import hashlib
                    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
                
                hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
                password_hash = hashed.decode('utf-8')
                
                cur.execute("""
                    INSERT INTO users (user_name, user_password, apikeys, balence, uid, is_admin, email, max_sessions)
                    VALUES (?, ?, '', 0.0, ?, 0, '', 1)
                """, (username, password_hash, uid))
                conn.commit()
        finally:
            conn.close()
        
        return f"User created: {username} (UID: {uid})\n"
    
    async def _user_delete(self, identifier: str) -> str:
        """删除用户（支持用户名或UID）"""
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        if user['is_admin']:
            return "Error: Cannot delete admin user\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                
                # 删除用户
                cur.execute("DELETE FROM users WHERE user_name = ?", (username,))
                # 删除充值请求
                cur.execute("DELETE FROM recharge_requests WHERE user_name = ?", (username,))
                # 删除会话
                cur.execute("DELETE FROM sessions WHERE user_name = ?", (username,))
                conn.commit()
        finally:
            conn.close()
        
        return f"User deleted: {username}\n"
    
    async def _user_password(self, identifier: str, new_password: str) -> str:
        """修改用户密码（支持用户名或UID）"""
        import bcrypt
        
        # 密码强度检查
        if len(new_password) < 6:
            return "Error: Password too short (min 6 chars)\n"
        if not any(c.isalpha() for c in new_password):
            return "Error: Password must contain at least one letter\n"
        if not any(c.isdigit() for c in new_password):
            return "Error: Password must contain at least one digit\n"
        
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                
                # 哈希密码
                if len(new_password.encode('utf-8')) > 72:
                    import hashlib
                    new_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
                
                hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12))
                password_hash = hashed.decode('utf-8')
                
                cur.execute(
                    "UPDATE users SET user_password = ? WHERE user_name = ?",
                    (password_hash, username)
                )
                conn.commit()
        finally:
            conn.close()
        
        return f"Password updated for user: {username}\n"
    
    async def _user_email(self, identifier: str, email: str) -> str:
        """设置/修改用户邮箱（支持用户名或UID）"""
        import re
        
        # 简单的邮箱格式验证
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return "Error: Invalid email format\n"
        
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE users SET email = ? WHERE user_name = ?",
                    (email, username)
                )
                conn.commit()
        finally:
            conn.close()
        
        return f"Email updated for user: {username} -> {email}\n"
    
    async def _user_admin(self, identifier: str, is_admin_str: str) -> str:
        """设置/取消管理员（支持用户名或UID）"""
        try:
            is_admin = int(is_admin_str)
            if is_admin not in (0, 1):
                raise ValueError
        except ValueError:
            return "Error: is_admin must be 0 or 1\n"
        
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE users SET is_admin = ? WHERE user_name = ?",
                    (is_admin, username)
                )
                conn.commit()
        finally:
            conn.close()
        
        role = '管理员' if is_admin else '普通用户'
        return f"User {username} role updated to: {role}\n"
    
    async def _user_balence(self, identifier: str, amount_str: str) -> str:
        """调整余额（支持用户名或UID）"""
        try:
            amount = float(amount_str)
        except ValueError:
            return "Error: Invalid amount\n"
        
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                
                new_balence = user['balence'] + amount
                if new_balence < 0:
                    new_balence = 0
                
                cur.execute(
                    "UPDATE users SET balence = ? WHERE user_name = ?",
                    (new_balence, username)
                )
                conn.commit()
        finally:
            conn.close()
        
        op = '增加' if amount >= 0 else '减少'
        return f"User {username} balence {op} {abs(amount):.4f} 元, 当前余额: {new_balence:.6f} 元\n"

    async def _user_overdraft(self, identifier: str, amount_str: str) -> str:
        """设置用户超支限额"""
        try:
            amount = float(amount_str)
        except ValueError:
            return "Error: amount must be a number\n"
        
        if amount < 0:
            return "Error: amount cannot be negative\n"
        
        user_info = await self._get_user_by_identifier(identifier)
        if not user_info:
            return f"Error: User '{identifier}' not found\n"
        
        username = user_info['user_name']
        old_overdraft = user_info.get('max_overdraft', 0) or 0
        
        async with self._get_db() as conn:
            await conn.execute(
                "UPDATE users SET max_overdraft = ? WHERE user_name = ?",
                (amount, username)
            )
            await conn.commit()
        
        return f"User {username} overdraft limit set: {old_overdraft:.6f} -> {amount:.6f} 元\n"
    
    async def _user_ban(self, identifier: str, reason: str) -> str:
        """封禁用户（支持用户名或UID）"""
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        if user['is_admin']:
            return "Error: Cannot ban admin user\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                
                cur.execute("""
                    UPDATE users SET is_banned = 1, ban_reason = ? WHERE user_name = ?
                """, (reason, username))
                
                # 踢掉所有会话
                cur.execute("DELETE FROM sessions WHERE user_name = ?", (username,))
                conn.commit()
        finally:
            conn.close()
        
        return f"User banned: {username}\nReason: {reason}\nAll sessions have been kicked.\n"
    
    async def _user_unban(self, identifier: str) -> str:
        """解封用户（支持用户名或UID）"""
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expire_at = NULL
                    WHERE user_name = ?
                """, (username,))
                conn.commit()
        finally:
            conn.close()
        
        return f"User unbanned: {username}\n"
    
    async def _user_clear(self, identifier: str, types_str: str) -> str:
        """清除用户数据（支持用户名或UID）
        types: apikeys, sessions, posts, friends, messages, transactions
        """
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        types = [t.strip().lower() for t in types_str.split(',') if t.strip()]
        
        if not types:
            return "Error: No clear types specified\n"
        
        valid_types = {'apikeys', 'sessions', 'posts', 'friends', 'messages', 'transactions'}
        invalid_types = set(types) - valid_types
        if invalid_types:
            return f"Error: Invalid types: {', '.join(invalid_types)}\nValid types: {', '.join(sorted(valid_types))}\n"
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                results = []
                
                if 'apikeys' in types:
                    cur.execute("UPDATE users SET apikeys = '' WHERE user_name = ?", (username,))
                    results.append(f"API Keys 已清除")
                
                if 'sessions' in types:
                    cur.execute("DELETE FROM sessions WHERE user_name = ?", (username,))
                    results.append(f"会话已清除 ({cur.rowcount} 个)")
                
                if 'posts' in types:
                    try:
                        cur.execute("DELETE FROM posts WHERE author = ?", (username,))
                        results.append(f"帖子已清除 ({cur.rowcount} 条)")
                    except Exception as e:
                        results.append(f"帖子清除失败: {str(e)}")
                
                if 'friends' in types:
                    try:
                        cur.execute("DELETE FROM friends WHERE user_name = ? OR friend_name = ?", (username, username))
                        results.append(f"好友关系已清除 ({cur.rowcount} 条)")
                    except Exception as e:
                        results.append(f"好友清除失败: {str(e)}")
                
                if 'messages' in types:
                    try:
                        cur.execute("DELETE FROM messages WHERE sender = ? OR receiver = ?", (username, username))
                        results.append(f"消息已清除 ({cur.rowcount} 条)")
                    except Exception as e:
                        results.append(f"消息清除失败: {str(e)}")
                
                if 'transactions' in types:
                    try:
                        cur.execute("DELETE FROM transactions WHERE user_name = ?", (username,))
                        results.append(f"交易记录已清除 ({cur.rowcount} 条)")
                    except Exception as e:
                        results.append(f"交易记录清除失败: {str(e)}")
                
                conn.commit()
        finally:
            conn.close()
        
        lines = [f"用户 {username} 数据清除结果", "=" * 40]
        lines.extend(results)
        return '\n'.join(lines) + '\n'
    
    async def cmd_session(self, args) -> str:
        """会话管理"""
        if not args:
            return "Usage: session <list|kick|kickall> ...\n"
        
        subcmd = args[0].lower()
        
        if subcmd == 'list':
            if len(args) < 2:
                return "Usage: session list <user|uid>\n"
            return await self._session_list(args[1])
        elif subcmd == 'kick':
            if len(args) < 2:
                return "Usage: session kick <session_id>\n"
            return await self._session_kick(args[1])
        elif subcmd == 'kickall':
            if len(args) < 2:
                return "Usage: session kickall <user|uid>\n"
            return await self._session_kickall(args[1])
        else:
            return f"Unknown session subcommand: {subcmd}\n"
    
    async def _session_list(self, identifier: str) -> str:
        """列出用户活跃会话（支持用户名或UID）"""
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT session_id, user_agent, ip_address, created_at, last_active_at, expires_at
                    FROM sessions
                    WHERE user_name = ? AND expires_at > datetime('now')
                    ORDER BY last_active_at DESC
                """, (username,))
                rows = cur.fetchall()
        finally:
            conn.close()
        
        if not rows:
            return f"No active sessions for user: {username}\n"
        
        lines = [f"用户 {username} 的活跃会话 ({len(rows)} 个)", "=" * 80]
        lines.append(f"{'会话ID':<36} {'IP':<16} {'最后活跃':<20} {'过期时间':<20}")
        lines.append("-" * 80)
        
        for row in rows:
            sid = row['session_id'][:36]
            ip = row['ip_address'] or '-'
            last_active = row['last_active_at'] or '-'
            expires = row['expires_at'] or '-'
            lines.append(f"{sid:<36} {ip:<16} {last_active:<20} {expires:<20}")
            if row['user_agent']:
                lines.append(f"  设备: {row['user_agent'][:80]}")
        
        return '\n'.join(lines) + '\n'
    
    async def _session_kick(self, session_id: str) -> str:
        """踢掉指定会话"""
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
                rows_affected = cur.rowcount
        finally:
            conn.close()
        
        if rows_affected > 0:
            return f"Session kicked: {session_id}\n"
        else:
            return f"Session not found: {session_id}\n"
    
    async def _session_kickall(self, identifier: str) -> str:
        """踢掉用户所有会话（支持用户名或UID）"""
        user = _get_user_by_identifier(identifier)
        if not user:
            return f"User not found: {identifier}\n"
        
        username = user['user_name']
        
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM sessions WHERE user_name = ?", (username,))
                conn.commit()
                rows_affected = cur.rowcount
        finally:
            conn.close()
        
        return f"Kicked {rows_affected} sessions for user: {username}\n"
    
    async def cmd_key(self, args) -> str:
        """密钥管理"""
        if not args:
            return "Usage: key <refresh>\n"
        
        subcmd = args[0].lower()
        
        if subcmd == 'refresh':
            # 刷新 RSA 密钥对
            from .rcon_crypto import generate_rsa_keypair, save_keypair, RSA_KEY_SIZE, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE
            private_pem, public_pem = generate_rsa_keypair()
            save_keypair(private_pem, public_pem)
            
            return (
                f"RSA 密钥对已刷新！\n"
                f"密钥长度: RSA {RSA_KEY_SIZE} 位\n"
                f"私钥文件: {PRIVATE_KEY_FILE}\n"
                f"公钥文件: {PUBLIC_KEY_FILE}\n"
                f"重要提示：所有使用旧公钥的 RCON 连接将失效，请分发新的公钥\n"
            )
        else:
            return f"Unknown key subcommand: {subcmd}\n"
    
    async def cmd_cleanup(self, args) -> str:
        """清理过期会话"""
        conn = _get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM sessions WHERE expires_at <= datetime('now')")
                conn.commit()
                rows_affected = cur.rowcount
        finally:
            conn.close()
        
        return f"Cleaned up {rows_affected} expired sessions.\n"
    
    async def cmd_exit(self, args) -> str:
        """退出"""
        return "__EXIT__"


# ========== RCON 服务器 ==========

async def handle_rcon_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """处理 RCON 客户端连接"""
    addr = writer.get_extra_info('peername')
    logging.info(f"RCON client connected: {addr}")
    
    handler = RCONCommandHandler()
    authenticated = False
    
    try:
        # 欢迎信息
        writer.write(b"RCON Server v1.0\n")
        writer.write(b"Authentication required. Send key first.\n")
        writer.write(b"Key: ")
        await writer.drain()
        
        # 读取密钥
        key_data = await reader.readline()
        if not key_data:
            return
        
        client_key = key_data.decode('utf-8').strip()
        expected_key = get_rcon_key()
        
        if client_key != expected_key:
            writer.write(b"Authentication failed!\n")
            await writer.drain()
            logging.warning(f"RCON auth failed from {addr}")
            return
        
        authenticated = True
        logging.info(f"RCON client authenticated: {addr}")
        
        writer.write(b"\nAuthentication successful!\n")
        writer.write(b"Type 'help' for available commands.\n")
        writer.write(b"\nrcon> ")
        await writer.drain()
        
        # 命令循环
        while True:
            data = await reader.readline()
            if not data:
                break
            
            command = data.decode('utf-8').strip()
            if not command:
                writer.write(b"rcon> ")
                await writer.drain()
                continue
            
            result = await handler.handle(command)
            
            if result == "__EXIT__":
                writer.write(b"Goodbye!\n")
                await writer.drain()
                break
            
            writer.write(result.encode('utf-8'))
            writer.write(b"\nrcon> ")
            await writer.drain()
    
    except Exception as e:
        logging.error(f"RCON client error: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        logging.info(f"RCON client disconnected: {addr}")


async def start_rcon_server():
    """启动 RCON 服务器"""
    # 确保 system_config 表存在
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS system_config (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    finally:
        conn.close()
    
    # 确保密钥存在
    get_rcon_key()
    
    # 创建 SSL 上下文
    try:
        ssl_ctx = create_ssl_context()
    except ImportError:
        logging.warning("cryptography library not found, RCON will run without TLS")
        ssl_ctx = None
    
    server = await asyncio.start_server(
        handle_rcon_client,
        '0.0.0.0',
        RCON_PORT,
        ssl=ssl_ctx
    )
    
    key = get_rcon_key()
    logging.info(f"RCON server started on port {RCON_PORT} (TLS: {'yes' if ssl_ctx else 'no'})")
    logging.info(f"RCON key: {key}")
    
    return server


if __name__ == '__main__':
    # 测试用
    async def main():
        server = await start_rcon_server()
        async with server:
            await server.serve_forever()
    
    asyncio.run(main())
