"""plugin.sync —— 同步插件的 API 面（继承 SyncPlugin 时使用）。

模块一览：
    system     logger / get_logger / bus / Plugin / SyncPlugin
    pages      add_page / Wrappers / PageHandle
    argument   NeedArgument / resolve_arg
    user       UserInfo / resolve_user_info
    config     Config / ConfigMethod / field / resolve
    info       plugins / PluginType

所有这些名字都可从 plugin.sync 顶层直接导入。注意：它们与 plugin.async
共享同一份实现，核心函数经 dual() 包装后在同步语境返回结果、在异步语境返回
可 await 协程，因此两套包可以混用而不冲突。
"""
from .system import logger, get_logger, bus, Plugin, SyncPlugin
from .pages import add_page, serve_assets, Wrappers, PageHandle
from .argument import NeedArgument, resolve_arg
from .user import UserInfo, resolve_user_info
from .config import Config, ConfigMethod, field, resolve
from .info import plugins, PluginType

__all__ = [
    "logger", "get_logger", "bus", "Plugin", "SyncPlugin",
    "add_page", "serve_assets", "Wrappers", "PageHandle",
    "NeedArgument", "resolve_arg",
    "UserInfo", "resolve_user_info",
    "Config", "ConfigMethod", "field", "resolve",
    "plugins", "PluginType",
]
