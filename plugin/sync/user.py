"""plugin.sync.user —— 当前登录用户信息抽象与解析器。

    from plugin.sync.user import UserInfo
    from plugin.sync.user import resolve_user_info   # 同步 call / await 均可
"""
from ..core.api_impl import UserInfo, resolve_user_info, guest

__all__ = ["UserInfo", "resolve_user_info", "guest"]
