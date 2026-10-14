"""兼容旧式导入：from plugin.config import Config, ConfigMethod, field, resolve"""
from .core.config import Config, ConfigMethod, field, resolve

__all__ = ["Config", "ConfigMethod", "field", "resolve"]
