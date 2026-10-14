"""插件配置系统。

设计目标：让插件像用户示例那样声明自己的配置项，并支持多种取值来源：

    class PLConfig(Config):
        # 简写：直接把 ConfigMethod 当默认值 → 该字段用此来源，并按类型自动给默认值
        for_anyone: bool = ConfigMethod.AskAdmin
        # 或显式写法：
        title: str = field(default="插件列表", method=ConfigMethod.File)

- ``ConfigMethod.Default``  : 永远使用默认值，忽略外部输入
- ``ConfigMethod.File``     : 从 plugins.json / plugins.yaml 读取（管理员维护）
- ``ConfigMethod.Env``      : 从环境变量 ``PLUGIN_<插件名大写>_<字段大写>`` 读取
- ``ConfigMethod.AskAdmin`` : 必须由管理员提供（FILE 或 ENV）；缺失时回退默认值并告警

取值优先级：Env > File > Default。
"""
from __future__ import annotations

import enum
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional, get_type_hints

from .exceptions import PluginConfigError

logger = logging.getLogger("apiproxy.plugins")

_MISSING = object()


class ConfigMethod(enum.Enum):
    Default = "default"
    File = "file"
    Env = "env"
    AskAdmin = "ask_admin"


@dataclass
class Field:
    """单个配置项的声明。"""

    default: Any = None
    method: ConfigMethod = ConfigMethod.File
    description: str = ""

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"Field(default={self.default!r}, method={self.method.value})"


def field(default: Any = None,
          method: ConfigMethod = ConfigMethod.File,
          description: str = "") -> Field:
    """声明一个配置项（推荐显式用法）。"""
    return Field(default=default, method=method, description=description)


def _auto_default(hint: Any) -> Any:
    """按类型推断一个合理的「未提供时」默认值。"""
    if hint is bool:
        return False
    if hint is int:
        return 0
    if hint is float:
        return 0.0
    if hint is str:
        return ""
    if hint in (list, dict):
        return hint()
    return None


class _ConfigMeta(type):
    """收集注解与默认值，构建 ``_fields`` 字段表（含基类继承）。"""

    def __new__(mcs, name, bases, ns):
        annotations = ns.get("__annotations__", {})
        fields: dict = {}
        for base in bases:
            base_fields = getattr(base, "_fields", None)
            if isinstance(base_fields, dict):
                fields.update(base_fields)

        for fname, ftype in annotations.items():
            # 下划线开头的注解是内部/私有成员（如基类的 ``_fields``），不当作配置字段，
            # 否则 __init__ 会用它的默认值把实例属性覆盖掉。
            if fname.startswith("_"):
                continue
            default = ns.get(fname, None)
            if isinstance(default, Field):
                fields[fname] = default
            elif isinstance(default, ConfigMethod):
                # 简写： ``for_anyone: bool = ConfigMethod.AskAdmin``
                fields[fname] = Field(default=_auto_default(ftype), method=default)
            else:
                # 裸默认值 → 视为 FILE 来源
                fields[fname] = Field(default=default, method=ConfigMethod.File)
        ns["_fields"] = fields
        return super().__new__(mcs, name, bases, ns)


class Config(metaclass=_ConfigMeta):
    """所有插件配置类的基类。子类用类注解声明字段，管理器加载时调用 resolve 构建实例。"""

    _fields: dict

    def __init__(self, values: Optional[dict] = None):
        values = values or {}
        for fname, fld in self._fields.items():
            setattr(self, fname, values.get(fname, fld.default))

    @classmethod
    def schema(cls) -> dict:
        return dict(cls._fields)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self._fields}

    def __repr__(self) -> str:  # pragma: no cover
        inner = ", ".join(f"{k}={getattr(self, k)!r}" for k in self._fields)
        return f"{self.__class__.__name__}({inner})"


def _coerce(value: Any, hint: Any) -> Any:
    """按字段注解类型对字符串配置值做强制转换。"""
    if value is None:
        return None
    if hint is bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "y", "on")
    if hint is int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    if hint is float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return value
    return value


def resolve(cls: type, plugin_name: str, file_values: Optional[dict] = None) -> "Config":
    """根据声明来源解析出配置实例。

    Args:
        cls         : 插件的 Config 子类
        plugin_name : 插件名（用于拼环境变量名）
        file_values : 来自 plugins.json/yaml 的该插件配置字典
    """
    if not (isinstance(cls, type) and issubclass(cls, Config)):
        raise PluginConfigError(f"{cls!r} 不是 Config 子类")

    try:
        hints = get_type_hints(cls)
    except Exception:  # pragma: no cover - 注解异常时退化为无类型
        hints = {}

    env_prefix = f"PLUGIN_{plugin_name.upper()}_"
    values: dict = {}

    for fname, fld in cls._fields.items():
        val = _MISSING

        # 1) 环境变量（最高优先级）
        if fld.method in (ConfigMethod.Env, ConfigMethod.AskAdmin):
            env_name = f"{env_prefix}{fname.upper()}"
            if env_name in os.environ:
                val = os.environ[env_name]

        # 2) 配置文件
        if val is _MISSING and fld.method in (ConfigMethod.File, ConfigMethod.AskAdmin):
            if isinstance(file_values, dict) and fname in file_values:
                val = file_values[fname]

        # 3) 缺失处理
        if val is _MISSING:
            if fld.method is ConfigMethod.AskAdmin:
                logger.warning(
                    "插件 %s 的配置项 %s 未由管理员提供，使用默认值 %r",
                    plugin_name, fname, fld.default,
                )
            val = fld.default

        values[fname] = _coerce(val, hints.get(fname))

    return cls(values)
