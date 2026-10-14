"""plugin.aio.system —— 异步插件的系统级工具。

典型用法：
    from plugin.aio.system import logger, AsyncPlugin, get_logger, bus
    from plugin.aio.pages import add_page, Wrappers

与 plugin.sync.system 的区别仅在于默认导出的基类是 AsyncPlugin；
logger / bus 等是完全相同的对象。
"""
from ..core.runtime import logger, get_logger, bus
from ..core.base import Plugin, AsyncPlugin

__all__ = ["logger", "get_logger", "bus", "Plugin", "AsyncPlugin"]
