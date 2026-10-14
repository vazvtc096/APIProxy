"""plugin.sync.config —— 插件配置声明。

    class PLConfig(Config):
        for_anyone: bool = ConfigMethod.AskAdmin     # 简写
        title: str = field(default="列表", method=ConfigMethod.File)
"""
from ..core.config import Config, ConfigMethod, field, resolve

__all__ = ["Config", "ConfigMethod", "field", "resolve"]
