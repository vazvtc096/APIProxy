"""请求上下文辅助：客户端 IP 与 User-Agent 获取。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
from quart import request

from .cloudflare import get_client_ip as _cf_get_client_ip


def _get_client_ip():
    """获取客户端真实IP（兼容反向代理 / Cloudflare）"""
    return _cf_get_client_ip()


def _get_user_agent():
    """获取客户端User-Agent"""
    return request.headers.get('User-Agent', 'unknown')[:500]  # 限制长度
