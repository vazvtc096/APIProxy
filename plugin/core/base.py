"""插件基类。

三个层次：
- ``Plugin``     : 公共基类，提供元信息声明、配置注入、包内资源访问、便捷 add_page。
- ``SyncPlugin`` : 同步插件，生命周期与处理函数均为普通 ``def``。
- ``AsyncPlugin``: 异步插件，生命周期与处理函数为 ``async def``。

双模 API（add_page / Wrappers / resolve_user_info 等）会根据调用方语境
（同步还是协程）自动选择 call 或 await，因此两个基类的使用方式完全一致，
区别仅在于方法本身是不是 async。

插件包内的任意资源（README、模板、前端静态文件……）可以自取：

    self.read_text("README.md")            # 读本插件包内的文本文件
    self.read_bytes("assets/logo.png")     # 读二进制
    self.serve_assets("/demo-static")      # 把 assets/ 目录挂成一个静态路由
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .info import PluginMeta, PluginType


class Plugin:
    # ---- 插件元信息（子类覆盖；plugin.json 清单里的同名字段优先）----
    name: str = ""
    version: str = "0.0.0"
    description: str = ""
    plugin_type: PluginType = PluginType.SYSTEM
    Config = None          # 可选：插件的 Config 子类
    mode: Optional[str] = None  # 'sync' | 'async' | None（基类未定）

    def __init__(self, config: Any = None):
        self.config = config
        self._manager: Any = None
        self._meta: Optional[PluginMeta] = None
        self._package: Any = None   # core.archive.PluginPackage，可能为 None

    # ---- 便捷访问 ----
    @property
    def log(self) -> logging.Logger:
        return logging.getLogger(
            f"apiproxy.plugins.{self.name or self.__class__.__name__}")

    @property
    def manager(self):
        return self._manager

    @property
    def meta(self) -> Optional[PluginMeta]:
        return self._meta

    @property
    def package(self):
        """本插件的来源包（目录或 zip），可读取清单、README 与任意资源。"""
        if self._package is None and self._meta is not None:
            self._package = getattr(self._meta, "package", None)
        return self._package

    @property
    def source_dir(self) -> str:
        """包所在的磁盘路径（zip 形态下是 zip 文件路径，不是解压目录）。"""
        return getattr(self.package, "path", "") or ""

    # ---- 包内资源 ----
    def resource_exists(self, member: str) -> bool:
        pkg = self.package
        return bool(pkg) and pkg.exists(member)

    def read_bytes(self, member: str) -> bytes:
        """读取本插件包内资源（二进制）。

        Args:
            member: 包内相对路径，如 ``assets/logo.png``
        """
        pkg = self.package
        if pkg is None:
            raise FileNotFoundError("插件未绑定来源包，无法读取资源")
        return pkg.read_bytes(member)

    def read_text(self, member: str, encoding: str = "utf-8") -> str:
        """读取本插件包内文本资源（如 README.md）。"""
        return self.read_bytes(member).decode(encoding, errors="replace")

    def serve_assets(self, rule_prefix: str, subdir: str = "assets",
                     **kwargs):
        """把包内某个目录挂成静态路由，双模返回值同 add_page。

        例：``self.serve_assets("/demo", "assets")`` 后，
        ``/demo/app.js`` 会返回包内 ``assets/app.js``。
        """
        from .api_impl import serve_assets
        return serve_assets(rule_prefix, subdir=subdir, **kwargs)

    def add_page(self, *args, **kwargs):
        """便捷封装，等价于 plugin.sync.pages.add_page（双模）。"""
        from .api_impl import add_page
        return add_page(*args, **kwargs)

    # ---- 生命周期（子类按需重写）----
    def on_load(self) -> None:
        """插件被加载、app 可用时调用。在此注册路由 / 启动资源。"""

    def on_unload(self) -> None:
        """插件卸载时调用。应释放资源、关闭已注册的路由。"""


class SyncPlugin(Plugin):
    """同步插件：on_load / on_unload / 请求处理函数均为普通函数。"""

    mode = "sync"

    def on_load(self) -> None:  # pragma: no cover - 默认空实现
        ...

    def on_unload(self) -> None:  # pragma: no cover
        ...


class AsyncPlugin(Plugin):
    """异步插件：on_load / on_unload / 请求处理函数均为 async 函数。"""

    mode = "async"

    async def on_load(self) -> None:  # pragma: no cover
        ...

    async def on_unload(self) -> None:  # pragma: no cover
        ...
