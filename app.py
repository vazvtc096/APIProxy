"""Quart 应用实例创建与配置。

此模块创建全局 Quart app 实例，加载配置、设置 session 安全参数。
所有路由模块通过 from .app import app 获取应用实例。
"""
import os
import secrets
import logging
import datetime as _dt
from pathlib import Path
from quart import Quart
from quart.json.provider import DefaultJSONProvider as _DefaultJSONProvider
from .configs import SSL_ENABLED, TIMEZONE_OFFSET_HOURS, IP_ACCESS_MODE

app = Quart(__name__)

# 模板与静态文件目录
BASE_DIR = Path(__file__).resolve().parent
app.template_folder = str(BASE_DIR / 'templates')
app.static_folder = str(BASE_DIR / 'static')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# Session 安全配置
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# SESSION_COOKIE_SECURE：SSL 开启时必然加；IP 访问管控启用（secure/audit/deny）时也强制加——
# 会话 cookie 是高价值资产，管控模式下不该有任何经明文 HTTP 传输的口子
# （Secure 属性让浏览器拒绝经明文 HTTP 收发该 cookie；公网经 cloudflared 浏览器侧是
# HTTPS 不受影响，本地 127.0.0.1 浏览器视为 trustworthy 同样可用）
app.config['SESSION_COOKIE_SECURE'] = bool(SSL_ENABLED or IP_ACCESS_MODE != 'allow')
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


def _detect_local_utc_offset() -> _dt.timedelta:
    """当前系统本地时区相对 UTC 的偏移。显式配置时按小时数覆盖，否则自动检测。"""
    if TIMEZONE_OFFSET_HOURS is not None:
        return _dt.timedelta(hours=TIMEZONE_OFFSET_HOURS)
    try:
        offset = _dt.datetime.now().astimezone().utcoffset()
        return offset if offset is not None else _dt.timedelta(0)
    except Exception:
        return _dt.timedelta(0)


_LOCAL_UTC_OFFSET = _detect_local_utc_offset()


class _LocalTimezoneJSONProvider(_DefaultJSONProvider):
    """把 naive datetime 视为服务器本地时刻来序列化。

    背景：数据库 timestamp without time zone 存的是「本地墙钟时刻」（服务器本地时区），
    但 Quart 默认 JSON provider 会把 naive datetime 序列化成 RFC7231 GMT 字符串，
    前端 new Date() 将其当 UTC 再转浏览器本地，导致展示偏移错误。
    这里显式标注服务器本地时区后输出 ISO 8601（带 +HH:MM），前端解析即正确。
    naive date 输出 ISO 日期；其余类型回退默认行为。
    """
    def default(self, o):
        if isinstance(o, _dt.datetime):
            if o.tzinfo is None:
                o = o.replace(tzinfo=_dt.timezone(_LOCAL_UTC_OFFSET))
            return o.isoformat(timespec="seconds")
        if isinstance(o, _dt.date):
            return o.isoformat()
        return super().default(o)


app.json = _LocalTimezoneJSONProvider(app)
