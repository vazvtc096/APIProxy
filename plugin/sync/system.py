"""plugin.sync.system —— 同步插件的系统级工具。

典型用法：
    from plugin.sync.system import logger, SyncPlugin, get_logger, bus
    from plugin.sync.pages import add_page, Wrappers
"""
from ..core.runtime import logger, get_logger, bus
from ..core.base import Plugin, SyncPlugin

__all__ = ["logger", "get_logger", "bus", "Plugin", "SyncPlugin"]
