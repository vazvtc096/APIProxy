"""plugin.aio.config —— 插件配置声明（与 sync 版共享实现）。

    class PLConfig(Config):
        for_anyone: bool = ConfigMethod.AskAdmin
"""
from ..core.config import Config, ConfigMethod, field, resolve

__all__ = ["Config", "ConfigMethod", "field", "resolve"]
