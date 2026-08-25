"""
邮箱验证码工具模块
支持通过 SMTP 发送验证码，验证码存储在内存中，带过期时间
"""
import smtplib
import time
import os
import base64
from email.mime.text import MIMEText
from email.header import Header
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from .configs import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, TOKEN_SECRET

# Fernet 密钥（用于加密验证码 / 密码重置令牌）
_fernet_key: bytes | None = None


def _get_fernet() -> Fernet:
    global _fernet_key
    if _fernet_key is not None:
        return Fernet(_fernet_key)
    if TOKEN_SECRET:
        raw = TOKEN_SECRET.encode('utf-8')
    else:
        raw = os.urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'email_utils_fernet', iterations=600000, backend=None)
    _fernet_key = base64.urlsafe_b64encode(kdf.derive(raw))
    return Fernet(_fernet_key)


def _encrypt_code(code: str) -> bytes:
    """使用 Fernet 加密验证码"""
    return _get_fernet().encrypt(code.encode('utf-8'))


def _decrypt_code(token: bytes) -> str:
    """解密 Fernet 加密的验证码"""
    return _get_fernet().decrypt(token).decode('utf-8')


# 验证码存储：{email: {'encrypted_code': <Fernet token>, 'expire_at': 1234567890, 'send_count': 0}}
_verification_codes = {}

# 验证码有效期（秒）
CODE_EXPIRE_SECONDS = 300  # 5 分钟
# 每天最多发送次数
MAX_SEND_PER_DAY = 10
# 发送间隔（秒）
SEND_INTERVAL = 60  # 1 分钟

# 验证码字符集：大写字母 + 数字（36 字符）
CODE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
CODE_CHARSET_LEN = len(CODE_CHARSET)  # 36
CODE_LENGTH = 6                        # 6 位 → 36^6 ≈ 2.1B 种组合


def _secure_randint(n: int) -> int:
    """返回 [0, n) 范围内无偏的随机整数（使用 cryptography 底层随机源）"""
    if n <= 0:
        return 0
    if n & (n - 1) == 0:
        # 2 的幂时直接取模不产生偏斜
        return int.from_bytes(os.urandom(1), 'big') % n
    threshold = 256 - (256 % n)
    while True:
        val = int.from_bytes(os.urandom(1), 'big')
        if val < threshold:
            return val % n


def generate_code() -> str:
    """生成 6 位字母数字验证码（0-9A-Z），使用 cryptography 底层 CSPRNG"""
    return ''.join(CODE_CHARSET[_secure_randint(CODE_CHARSET_LEN)] for _ in range(CODE_LENGTH))


def send_verification_email(email: str) -> tuple[bool, str]:
    """发送验证码邮件
    
    Returns:
        (success: bool, message: str)
    """
    if not SMTP_USER or not SMTP_PASS:
        return False, "邮箱服务未配置"
    
    # 检查发送频率
    now = time.time()
    record = _verification_codes.get(email, {})
    
    if record:
        # 检查发送间隔
        last_send_time = record.get('last_send_time', 0)
        if now - last_send_time < SEND_INTERVAL:
            wait_seconds = int(SEND_INTERVAL - (now - last_send_time))
            return False, f"发送太频繁，请 {wait_seconds} 秒后再试"
        
        # 检查每日发送次数
        today_start = int(now // 86400 * 86400)
        if record.get('today_start') == today_start:
            if record.get('send_count', 0) >= MAX_SEND_PER_DAY:
                return False, "今日发送次数已达上限"
        else:
            # 新的一天，重置计数
            record['send_count'] = 0
            record['today_start'] = today_start
    
    # 生成验证码
    code = generate_code()
    
    # 构造邮件内容
    subject = "Cloud LLM API 代理 - 注册验证码"
    body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 12px 12px 0 0;">
            <h2 style="color: white; margin: 0; font-size: 24px;">Cloud LLM API 代理</h2>
            <p style="color: rgba(255,255,255,0.9); margin: 8px 0 0 0; font-size: 14px;">邮箱验证码</p>
        </div>
        <div style="background: #fff; padding: 40px 30px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
            <p style="color: #333; font-size: 16px; margin: 0 0 20px 0;">您好，</p>
            <p style="color: #666; font-size: 14px; margin: 0 0 30px 0;">您正在注册 Cloud LLM API 代理账户，请使用以下验证码完成注册：</p>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 30px;">
                <span style="font-size: 36px; font-weight: bold; color: #667eea; letter-spacing: 8px;">{code}</span>
            </div>
            <p style="color: #999; font-size: 12px; margin: 0;">
                验证码有效期 5 分钟，请勿泄露给他人。<br>
                如果这不是您本人的操作，请忽略此邮件。
            </p>
        </div>
        <div style="text-align: center; color: #999; font-size: 12px; margin-top: 20px;">
            © 2024 Cloud LLM API 代理. All rights reserved.
        </div>
    </div>
    """
    
    try:
        # 创建邮件
        msg = MIMEText(body, 'html', 'utf-8')
        msg['From'] = Header(SMTP_FROM, 'utf-8')
        msg['To'] = Header(email, 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        
        # 发送邮件
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [email], msg.as_string())
        server.quit()
        
        # 保存验证码记录（Fernet 加密存储）
        _verification_codes[email] = {
            'encrypted_code': _encrypt_code(code),
            'expire_at': now + CODE_EXPIRE_SECONDS,
            'send_count': record.get('send_count', 0) + 1,
            'today_start': record.get('today_start', int(now // 86400 * 86400)),
            'last_send_time': now
        }
        
        return True, "验证码已发送，请查收邮件"
    
    except Exception as e:
        return False, f"邮件发送失败: {str(e)}"


def verify_code(email: str, code: str, expected_type: str = None, expected_username: str = None) -> tuple[bool, str]:
    """验证验证码

    参数:
        email: 邮箱
        code: 用户输入的验证码
        expected_type: 期望的验证码类型（'register' / 'password_reset'），用于防止跨用途复用
        expected_username: 密码重置时期望的用户名，确保验证码与账号绑定

    Returns:
        (success: bool, message: str)
    """
    record = _verification_codes.get(email)

    if not record:
        return False, "请先获取验证码"

    # 检查是否过期
    if time.time() > record['expire_at']:
        del _verification_codes[email]
        return False, "验证码已过期，请重新获取"

    # 检查验证码类型是否匹配（防止注册验证码用于密码重置等跨用途攻击）
    if expected_type is not None and record.get('type') != expected_type:
        del _verification_codes[email]
        return False, "验证码类型不匹配"

    # 检查用户名绑定（密码重置时，确保验证码属于该账号）
    if expected_username is not None and record.get('username') is not None and record.get('username') != expected_username:
        del _verification_codes[email]
        return False, "验证码与账号不匹配"

    # 解密并检查验证码
    try:
        stored_code = _decrypt_code(record['encrypted_code'])
        if stored_code != code:
            return False, "验证码错误"
    except Exception:
        return False, "验证码错误"

    # 验证成功，删除验证码（一次性使用）
    del _verification_codes[email]

    return True, "验证成功"


def cleanup_expired_codes():
    """清理过期的验证码（可定期调用）"""
    now = time.time()
    expired_emails = [
        email for email, record in _verification_codes.items()
        if now > record.get('expire_at', 0)
    ]
    for email in expired_emails:
        del _verification_codes[email]


def send_password_reset_email(email: str, username: str) -> tuple[bool, str]:
    """发送密码重置验证码邮件
    
    Args:
        email: 收件人邮箱
        username: 用户名
    
    Returns:
        (success: bool, message: str)
    """
    if not SMTP_USER or not SMTP_PASS:
        return False, "邮箱服务未配置"
    
    # 检查发送频率
    now = time.time()
    record = _verification_codes.get(email, {})
    
    if record:
        # 检查发送间隔
        last_send_time = record.get('last_send_time', 0)
        if now - last_send_time < SEND_INTERVAL:
            wait_seconds = int(SEND_INTERVAL - (now - last_send_time))
            return False, f"发送太频繁，请 {wait_seconds} 秒后再试"
        
        # 检查每日发送次数
        today_start = int(now // 86400 * 86400)
        if record.get('today_start') == today_start:
            if record.get('send_count', 0) >= MAX_SEND_PER_DAY:
                return False, "今日发送次数已达上限"
        else:
            # 新的一天，重置计数
            record['send_count'] = 0
            record['today_start'] = today_start
    
    # 生成验证码
    code = generate_code()
    
    # 构造邮件内容
    subject = "Cloud LLM API 代理 - 密码重置验证码"
    body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 12px 12px 0 0;">
            <h2 style="color: white; margin: 0; font-size: 24px;">Cloud LLM API 代理</h2>
            <p style="color: rgba(255,255,255,0.9); margin: 8px 0 0 0; font-size: 14px;">密码重置</p>
        </div>
        <div style="background: #fff; padding: 40px 30px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
            <p style="color: #333; font-size: 16px; margin: 0 0 20px 0;">您好，<strong>{username}</strong></p>
            <p style="color: #666; font-size: 14px; margin: 0 0 30px 0;">您正在请求重置密码，请使用以下验证码完成重置：</p>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 30px;">
                <span style="font-size: 36px; font-weight: bold; color: #667eea; letter-spacing: 8px;">{code}</span>
            </div>
            <p style="color: #999; font-size: 12px; margin: 0;">
                验证码有效期 5 分钟，请勿泄露给他人。<br>
                如果这不是您本人的操作，请忽略此邮件。
            </p>
        </div>
        <div style="text-align: center; color: #999; font-size: 12px; margin-top: 20px;">
            © 2024 Cloud LLM API 代理. All rights reserved.
        </div>
    </div>
    """
    
    try:
        # 创建邮件
        msg = MIMEText(body, 'html', 'utf-8')
        msg['From'] = Header(SMTP_FROM, 'utf-8')
        msg['To'] = Header(email, 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        
        # 发送邮件
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [email], msg.as_string())
        server.quit()
        
        # 保存验证码记录（Fernet 加密存储）
        _verification_codes[email] = {
            'encrypted_code': _encrypt_code(code),
            'expire_at': now + CODE_EXPIRE_SECONDS,
            'send_count': record.get('send_count', 0) + 1,
            'today_start': record.get('today_start', int(now // 86400 * 86400)),
            'last_send_time': now,
            'type': 'password_reset',
            'username': username
        }
        
        return True, "验证码已发送，请查收邮件"
    
    except Exception as e:
        return False, f"邮件发送失败: {str(e)}"


def send_login_alert_email(email: str, username: str, ip: str, user_agent: str, login_time: str,
                           device_type: str = '', risk_level: str = '', risk_details: list = None) -> tuple[bool, str]:
    """发送异地登录提醒邮件
    
    Args:
        email: 收件人邮箱
        username: 用户名
        ip: 登录IP地址
        user_agent: 浏览器UA
        login_time: 登录时间
    
    Returns:
        (success: bool, message: str)
    """
    if not SMTP_USER or not SMTP_PASS:
        return False, "邮箱服务未配置"
    
    # 构造邮件内容
    severity_labels = {'safe': '安全', 'warn': '警告', 'restrict': '限制(临时封禁1小时)', 'ban': '严重(临时封禁24小时)'}
    risk_label = severity_labels.get(risk_level, '') if risk_level else ''
    extra_rows = ''
    if device_type:
        extra_rows += f"""
                    <tr>
                        <td style="padding: 8px 0; color: #666;">设备类型：</td>
                        <td style="padding: 8px 0; color: #333;">{device_type}</td>
                    </tr>"""
    if risk_label:
        extra_rows += f"""
                    <tr>
                        <td style="padding: 8px 0; color: #666;">风险等级：</td>
                        <td style="padding: 8px 0; color: #c53030; font-weight: bold;">{risk_label}</td>
                    </tr>"""
    if risk_details:
        details_html = '<br>'.join(f"· {d}" for d in risk_details[:5])
        extra_rows += f"""
                    <tr>
                        <td style="padding: 8px 0; color: #666; vertical-align: top;">风险明细：</td>
                        <td style="padding: 8px 0; color: #333;">{details_html}</td>
                    </tr>"""
    subject = "Cloud LLM API 代理 - 异地登录提醒"
    body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 30px; border-radius: 12px 12px 0 0;">
            <h2 style="color: white; margin: 0; font-size: 24px;">⚠️ 安全提醒</h2>
            <p style="color: rgba(255,255,255,0.9); margin: 8px 0 0 0; font-size: 14px;">检测到异地登录</p>
        </div>
        <div style="background: #fff; padding: 40px 30px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
            <p style="color: #333; font-size: 16px; margin: 0 0 20px 0;">您好，<strong>{username}</strong></p>
            <p style="color: #666; font-size: 14px; margin: 0 0 30px 0;">我们检测到您的账号在新的设备/IP上登录，如果这不是您本人操作，请立即修改密码。</p>
            
            <div style="background: #fff5f5; border: 1px solid #fed7d7; padding: 20px; border-radius: 8px; margin-bottom: 30px;">
                <h4 style="color: #c53030; margin: 0 0 15px 0; font-size: 14px;">登录详情</h4>
                <table style="width: 100%; font-size: 13px;">
                    <tr>
                        <td style="padding: 8px 0; color: #666; width: 80px;">IP地址：</td>
                        <td style="padding: 8px 0; color: #333; font-family: monospace;">{ip}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #666;">登录时间：</td>
                        <td style="padding: 8px 0; color: #333;">{login_time}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #666;">设备信息：</td>
                        <td style="padding: 8px 0; color: #333; word-break: break-all;">{user_agent}</td>
                    </tr>{extra_rows}
                </table>
            </div>
            
            <p style="color: #999; font-size: 12px; margin: 0;">
                如果这是您本人的操作，可以忽略此邮件。<br>
                如果不是您本人操作，请立即修改密码，确保账号安全。
            </p>
        </div>
        <div style="text-align: center; color: #999; font-size: 12px; margin-top: 20px;">
            © 2024 Cloud LLM API 代理. All rights reserved.
        </div>
    </div>
    """
    
    try:
        # 创建邮件
        msg = MIMEText(body, 'html', 'utf-8')
        msg['From'] = Header(SMTP_FROM, 'utf-8')
        msg['To'] = Header(email, 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        
        # 发送邮件
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [email], msg.as_string())
        server.quit()
        
        return True, "提醒邮件已发送"
    
    except Exception as e:
        return False, f"邮件发送失败: {str(e)}"
