"""兼容旧式导入：from plugin.info import plugins, PluginType"""
from .core.info import plugins, PluginType, PluginMeta

__all__ = ["plugins", "PluginType", "PluginMeta"]
