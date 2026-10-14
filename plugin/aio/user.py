"""plugin.aio.user —— 当前登录用户信息抽象与解析器。

    from plugin.aio.user import UserInfo
    info = await resolve_user_info()   # 异步语境下推荐 await
"""
from ..core.api_impl import UserInfo, resolve_user_info, guest

__all__ = ["UserInfo", "resolve_user_info", "guest"]
