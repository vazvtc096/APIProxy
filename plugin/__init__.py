"""APIProxy 插件系统。

顶层包，提供最常用的导入入口：
    from plugin import Plugin, SyncPlugin, AsyncPlugin, get_plugin_manager
    from plugin import plugins, PluginType, load_plugins

按插件类型选用对应的 API 面：
    # 同步插件（继承 SyncPlugin）
    from plugin.sync.system import logger, SyncPlugin
    from plugin.sync.pages import add_page, serve_assets, Wrappers
    from plugin.sync.argument import NeedArgument
    from plugin.sync.user import UserInfo
    from plugin.sync.config import Config, ConfigMethod
    from plugin.sync.info import plugins, PluginType

    # 异步插件（继承 AsyncPlugin）
    from plugin.aio.system import logger, AsyncPlugin
    from plugin.aio.pages import add_page, serve_assets, Wrappers
    ...

两套 API 实际共享同一份实现：核心函数都经过 dual() 包装，能根据调用方语境
（同步 call 还是 await）自动切换，因此无需记忆「同步版 / 异步版」的差异。

插件在磁盘上的形态（两种等价，管理器自动识别）：

    plugins/DemoPlugin/        目录形态（开发态）
    plugins/DemoPlugin.zip     压缩包形态（分发态）

包内必须有 ``main.py`` 作为入口，可选 ``plugin.json`` 清单、``README.md``、
``LICENSE.md``、``requirements.txt`` 与任意资源文件。打包用：

    python -m plugin.core.pack plugins/DemoPlugin

开发时想改完代码自动生效（热重载，默认关闭）：

    PLUGIN_HOT_RELOAD=1            # 环境变量
    {"hot_reload": true}           # 或写进根 plugins.json
"""
from __future__ import annotations

import os
import sys

# 确保项目根目录在 sys.path 上，使 ``import plugin`` 与 ``import plugins`` 均可用，
# 无论 APIProxy 是以何种工作目录启动。
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from .core.base import Plugin, SyncPlugin, AsyncPlugin  # noqa: E402,F401
from .core.manager import get_plugin_manager, PluginManager  # noqa: E402,F401
from .core.info import plugins, PluginType, PluginMeta  # noqa: E402,F401
from .core.info import PLUGIN_API_VERSION  # noqa: E402,F401
from .core.archive import (  # noqa: E402,F401
    PluginPackage, iter_packages, open_package,
)
from .core.pack import pack_plugin, extract_plugin  # noqa: E402,F401
from .core.hotreload import (  # noqa: E402,F401
    HotReloader, get_hot_reloader,
    attach_hot_reload, start_hot_reload, stop_hot_reload,
)
from .core.runtime import logger, bus, get_logger  # noqa: E402,F401
from .core.exceptions import (  # noqa: E402,F401
    PluginError, PluginLoadError, PluginConfigError, PluginUnloadError,
)


def load_plugins(app=None, config_file: str = None):
    """加载 plugins/ 下的全部插件并挂载到给定 app（缺省取当前已创建的 app）。"""
    return get_plugin_manager().load_all(app=app, config_file=config_file)


__all__ = [
    "Plugin", "SyncPlugin", "AsyncPlugin",
    "get_plugin_manager", "PluginManager", "load_plugins",
    "plugins", "PluginType", "PluginMeta", "PLUGIN_API_VERSION",
    "PluginPackage", "open_package", "iter_packages",
    "pack_plugin", "extract_plugin",
    "HotReloader", "get_hot_reloader",
    "attach_hot_reload", "start_hot_reload", "stop_hot_reload",
    "logger", "bus", "get_logger",
    "PluginError", "PluginLoadError", "PluginConfigError", "PluginUnloadError",
]
