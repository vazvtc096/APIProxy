"""Quart 应用实例创建与配置。

此模块创建全局 Quart app 实例，加载配置、设置 session 安全参数。
所有路由模块通过 from .app import app 获取应用实例。
"""
import os
import secrets
import logging
from pathlib import Path
from quart import Quart
from .configs import SSL_ENABLED

app = Quart(__name__)

# 模板与静态文件目录
BASE_DIR = Path(__file__).resolve().parent
app.template_folder = str(BASE_DIR / 'templates')
app.static_folder = str(BASE_DIR / 'static')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# Session 安全配置
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = SSL_ENABLED
app.config['PERMANENT_SESSION_LIFETIME'] = 86400


def _load_session_secret() -> str:
    """加载或生成 session 密钥"""
    from .configs import SESSION_SECRET
    if SESSION_SECRET:
        return SESSION_SECRET
    secret_file = os.path.join(os.path.dirname(__file__), '.session_secret')
    try:
        if os.path.exists(secret_file):
            with open(secret_file, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except Exception:
        pass
    new_secret = secrets.token_hex(32)
    try:
        with open(secret_file, 'w', encoding='utf-8') as f:
            f.write(new_secret)
        os.chmod(secret_file, 0o600)
    except Exception:
        pass
    return new_secret


app.secret_key = _load_session_secret()
