"""plugin.aio.info —— 插件元信息与全局注册表（与 sync 版共享单例）。"""
from ..core.info import plugins, PluginType, PluginMeta

__all__ = ["plugins", "PluginType", "PluginMeta"]
