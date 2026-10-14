"""plugin.sync.info —— 插件元信息与全局注册表。

``plugins`` 是可被 jsonify 的全局单例。
"""
from ..core.info import plugins, PluginType, PluginMeta

__all__ = ["plugins", "PluginType", "PluginMeta"]
