"""plugin.aio —— 异步插件的 API 面（继承 AsyncPlugin 时使用）。

命名说明：这里本该叫 ``plugin.async``（与 ``plugin.sync`` 对仗），但 ``async``
是 Python 保留关键字，``from plugin.async.system import AsyncPlugin`` 在语法
层面就无法解析（编译器直接报 SyntaxError），因此沿用生态惯例取名为 ``aio``
（如 aiohttp / aiomysql）。模块布局与 plugin.sync 完全对称。

模块一览：
    system     logger / get_logger / bus / Plugin / AsyncPlugin
    pages      add_page / Wrappers / PageHandle
    argument   NeedArgument / resolve_arg
    user       UserInfo / resolve_user_info
    config     Config / ConfigMethod / field / resolve
    info       plugins / PluginType

与 plugin.sync 共享同一份实现。API 函数经 dual() 包装：在 async def 内部调用
返回可 await 的协程，在普通 def 内部调用则直接返回同步结果。所以即使这里写
了 await，将来把插件改成 SyncPlugin 去掉 await 也照样能跑。
"""
from .system import logger, get_logger, bus, Plugin, AsyncPlugin
from .pages import add_page, serve_assets, Wrappers, PageHandle
from .argument import NeedArgument, resolve_arg
from .user import UserInfo, resolve_user_info
from .config import Config, ConfigMethod, field, resolve
from .info import plugins, PluginType

__all__ = [
    "logger", "get_logger", "bus", "Plugin", "AsyncPlugin",
    "add_page", "serve_assets", "Wrappers", "PageHandle",
    "NeedArgument", "resolve_arg",
    "UserInfo", "resolve_user_info",
    "Config", "ConfigMethod", "field", "resolve",
    "plugins", "PluginType",
]
