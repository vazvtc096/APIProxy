"""插件系统异常定义。"""


class PluginError(Exception):
    """插件系统基础异常。"""


class PluginLoadError(PluginError):
    """插件加载（导入/实例化/on_load）阶段失败。"""


class PluginConfigError(PluginError):
    """插件配置解析失败。"""


class PluginUnloadError(PluginError):
    """插件卸载阶段失败。"""
