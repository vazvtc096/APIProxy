"""插件元信息与全局注册表。

对外暴露：
    from plugin.info import plugins, PluginType

- ``PluginType``        : 插件分类枚举
- ``PluginMeta``        : 单个插件的可序列化元信息（含来源包、作者、许可证等）
- ``plugins``           : 全局 PluginRegistry 单例，可被 jsonify（提供 to_dict）
- ``PLUGIN_API_VERSION``: 本内核的插件 API 版本，插件可用清单字段 min_api 要求下限
"""
from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional

# 插件 API 版本：破坏插件作者可见行为时才升主版本
PLUGIN_API_VERSION = "1.1.0"


class PluginType(enum.Enum):
    SYSTEM = "system"            # 系统级扩展（如管理、调度）
    WEB = "web"                  # 提供页面 / UI
    API = "api"                  # 提供接口 / 代理增强
    INTEGRATION = "integration"  # 与外部服务对接
    SOCIAL = "social"            # 社交 / 社区相关
    SECURITY = "security"        # 安全 / 风控


class PluginMeta:
    """单个插件的可序列化元信息。

    字段优先级：插件清单(plugin.json) > 类的类属性 > README/LICENSE 推断。
    ``package`` 保存来源包抽象（目录或 zip），用于读取包内资源。
    """

    def __init__(self,
                 name: str,
                 version: str = "0.0.0",
                 description: str = "",
                 plugin_type: PluginType = PluginType.SYSTEM,
                 enabled: bool = True,
                 instance: Any = None,
                 *,
                 plugin_id: str = "",
                 author: str = "",
                 license_name: str = "",
                 homepage: str = "",
                 tags: Optional[List[str]] = None,
                 requirements: Optional[List[str]] = None,
                 package: Any = None):
        self.name = name
        self.version = version
        self.description = description
        self.plugin_type = plugin_type
        self.enabled = enabled
        self.instance = instance
        self.plugin_id = plugin_id or name
        self.author = author
        self.license_name = license_name
        self.homepage = homepage
        self.tags = list(tags or [])
        self.requirements = list(requirements or [])
        self.package = package

    @property
    def source_format(self) -> str:
        """插件来源形态：'dir' / 'zip' / ''（无包信息）。"""
        return getattr(self.package, "fmt", "") if self.package else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "type": self.plugin_type.value
            if isinstance(self.plugin_type, PluginType) else str(self.plugin_type),
            "enabled": self.enabled,
            "author": self.author,
            "license": self.license_name,
            "homepage": self.homepage,
            "tags": self.tags,
            "format": self.source_format,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PluginMeta {self.plugin_id} v{self.version} [{self.source_format}]>"


class PluginRegistry:
    """已加载插件的注册表，可被 jsonify 直接序列化。"""

    def __init__(self) -> None:
        self._entries: Dict[str, PluginMeta] = {}

    def register(self, meta: PluginMeta) -> None:
        self._entries[meta.plugin_id] = meta

    def unregister(self, name: str) -> None:
        """按插件 id 或显示名注销。"""
        key = name if name in self._entries else None
        if key is None:
            for k, m in self._entries.items():
                if m.name == name:
                    key = k
                    break
        if key is not None:
            self._entries.pop(key, None)

    def get(self, name: str) -> Optional[PluginMeta]:
        if name in self._entries:
            return self._entries[name]
        for m in self._entries.values():
            if m.name == name:
                return m
        return None

    def list(self) -> List[Dict[str, Any]]:
        return [m.to_dict() for m in self._entries.values()]

    def to_dict(self) -> List[Dict[str, Any]]:
        # Wrappers.jsonify(plugins) 会调用此方法
        return self.list()

    def __iter__(self):
        return iter(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PluginRegistry size={len(self)}>"


# 全局单例
plugins = PluginRegistry()
