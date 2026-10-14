"""插件管理器：发现、加载、生命周期、卸载、重载。

对外暴露单例 ``get_plugin_manager()``。在 ``create_app()`` 中调用
``load_all(app=app)`` 即可把 plugins/ 下的插件挂载到应用。

支持的形态（都由 ``PluginPackage`` 统一封装，见 core/archive.py）：

    plugins/DemoPlugin.zip        分发态，内含 DemoPlugin/main.py
    plugins/DemoPlugin/main.py    开发态

包内约定成员：main.py（入口）、plugin.json（清单）、README.md、LICENSE.md、
requirements.txt、以及任意资源文件。

启用控制在根配置 plugins.json / plugins.yaml：

    {
      "enabled": ["pluginlist"],                 # 白名单（缺省表示全部启用）
      "pluginlist": {"enabled": false, "for_anyone": true}
    }
"""
from __future__ import annotations

import inspect
import json
import logging
import os
import shutil
from typing import Any, Dict, List, Optional

from .runtime import current_plugin, run_sync
from .config import Config, resolve as _resolve_config
from .info import (PLUGIN_API_VERSION, PluginMeta, PluginType,
                   plugins as _registry)
from .archive import (PluginPackage, iter_packages, open_package,
                      package_from_snapshot)
from .exceptions import PluginError, PluginLoadError
from .base import Plugin as _Plugin

logger = logging.getLogger("apiproxy.plugins")

# plugin/ 包所在根目录（plugin/core/manager.py → 上溯三级）
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _maybe_await(result: Any) -> Any:
    """执行生命周期钩子结果。

    同步钩子返回 None；异步钩子（async def on_load / on_unload）返回协程，
    交给 runtime.run_sync 执行 —— 它会自动处理「已有事件循环在运行」的情况
    （另起线程跑新循环），避免 asyncio.run 抛「loop already running」。
    """
    if inspect.isawaitable(result):
        try:
            return run_sync(result)
        except Exception as e:
            logger.error("插件生命周期异步函数执行失败：%s", e)
    return None


class PluginManager:
    def __init__(self, plugins_dir: Optional[str] = None):
        self.plugins_dir = plugins_dir or os.path.join(_ROOT, "plugins")
        self.app = None
        self._instances: Dict[str, Any] = {}          # plugin_id → 实例
        self._packages: Dict[str, PluginPackage] = {}  # plugin_id → 来源包
        self._metas: Dict[str, PluginMeta] = {}        # plugin_id → 元信息
        self._snapshots: Dict[str, Dict[str, bytes]] = {}  # plugin_id → 上一版源码快照
        self._enabled: Optional[set] = None
        self._configs: Dict[str, dict] = {}
        # 热重载开关：默认关。plugins.json 的 hot_reload 或环境变量 PLUGIN_HOT_RELOAD 可开
        self.hot_reload: bool = False
        self.hot_reload_interval: float = 1.0

    # ------------------------------------------------------------------
    # 配置
    # ------------------------------------------------------------------
    def set_app(self, app) -> None:
        self.app = app

    def _load_config_file(self, path: Optional[str] = None) -> None:
        candidates = [path] if path else [
            os.path.join(_ROOT, "plugins.json"),
            os.path.join(_ROOT, "plugins.yaml"),
        ]
        data: dict = {}
        for c in candidates:
            if not c or not os.path.isfile(c):
                continue
            try:
                if c.endswith(".json"):
                    with open(c, "r", encoding="utf-8") as f:
                        data = json.load(f)
                else:  # .yaml
                    import yaml
                    with open(c, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                break
            except Exception as e:
                logger.warning("读取插件配置文件 %s 失败：%s", c, e)

        enabled = data.get("enabled")
        self._enabled = set(enabled) if enabled else None

        # 热重载：环境变量优先，其次 plugins.json
        env_hot = os.environ.get("PLUGIN_HOT_RELOAD")
        if env_hot is not None:
            self.hot_reload = env_hot.strip().lower() in ("1", "true", "yes", "y", "on")
        else:
            self.hot_reload = bool(data.get("hot_reload", False))
        try:
            iv = os.environ.get("PLUGIN_HOT_RELOAD_INTERVAL") or data.get("hot_reload_interval")
            self.hot_reload_interval = float(iv) if iv else 1.0
        except (TypeError, ValueError):
            self.hot_reload_interval = 1.0

        self._configs = {}
        for key, val in data.items():
            if key == "enabled" or not isinstance(val, dict):
                continue
            self._configs[key] = val

    def _plugin_enabled(self, pkg: PluginPackage) -> bool:
        """白名单 + per-plugin ``enabled: false`` 双重判断。"""
        if self._enabled is not None and pkg.plugin_id not in self._enabled:
            return False
        return bool(self._configs.get(pkg.plugin_id, {}).get("enabled", True))

    # ------------------------------------------------------------------
    # 发现
    # ------------------------------------------------------------------
    def discover(self) -> List[PluginPackage]:
        """扫描插件目录，返回所有合法插件包（不负责启用判断）。"""
        return iter_packages(self.plugins_dir)

    def list_available(self) -> List[Dict[str, Any]]:
        """列出插件目录里的一切包及其启用状态（适合管理面板直接展示）。"""
        rows = []
        for pkg in self.discover():
            info = pkg.describe()
            info["enabled"] = self._plugin_enabled(pkg)
            info["loaded"] = pkg.plugin_id in self._instances
            info.update({
                "name": info.get("id"),
                "version": pkg.manifest.get("version", ""),
                "description": pkg.description,
            })
            rows.append(info)
        return rows

    # ------------------------------------------------------------------
    # 加载
    # ------------------------------------------------------------------
    def load_all(self, app=None, config_file: Optional[str] = None,
                 plugins_dir: Optional[str] = None) -> "PluginManager":
        if app is not None:
            self.app = app
        if plugins_dir:
            self.plugins_dir = plugins_dir
        self._load_config_file(config_file)

        for pkg in self.discover():
            if not self._plugin_enabled(pkg):
                logger.debug("插件 %s 未启用，跳过", pkg.plugin_id)
                continue
            try:
                self.load_package(pkg)
            except Exception as e:  # 单个插件失败不影响其余
                logger.exception("插件 %s 加载失败：%s", pkg.plugin_id, e)

        logger.info("插件系统加载完成，共启用 %d 个", len(self._instances))
        return self

    def load_path(self, path: str) -> Any:
        """按路径加载单个插件（目录或 zip），返回插件实例。"""
        return self.load_package(open_package(path))

    def install(self, zip_path: str, replace: bool = False) -> Any:
        """把外部的插件 zip 安装进插件目录并立即加载。

        Args:
            zip_path: 外部 zip 的路径
            replace : 目标已存在同名文件时是否覆盖
        """
        zip_path = os.path.abspath(zip_path)
        pkg = open_package(zip_path)               # 先校验是不是合法插件包
        target = os.path.join(self.plugins_dir, os.path.basename(zip_path))
        if os.path.exists(target) and not replace:
            raise PluginError(f"目标插件已存在：{target}（replace=True 可覆盖）")
        os.makedirs(self.plugins_dir, exist_ok=True)
        shutil.copy2(zip_path, target)
        logger.info("已安装插件：%s", target)

        installed = open_package(target)
        if not self._plugin_enabled(installed):
            logger.info("插件 %s 安装成功但未在启用名单内，未加载",
                        installed.plugin_id)
            return None

        # 已加载的同 id 插件视为覆盖安装：先卸载再加载新版
        if installed.plugin_id in self._instances:
            logger.info("插件 %s 已加载，执行覆盖安装", installed.plugin_id)
            self.unload(installed.plugin_id)
        return self.load_package(installed)

    def load_package(self, pkg: PluginPackage) -> Any:
        """加载单个插件包，注册到实例表与全局注册表。"""
        if pkg.plugin_id in self._instances:
            raise PluginLoadError(f"插件 {pkg.plugin_id} 已加载，请先卸载")

        try:
            pkg.check_compatibility(PLUGIN_API_VERSION)
            module = pkg.import_module()
        except Exception as e:
            raise PluginLoadError(f"导入失败：{e}")

        PluginCls = self._find_plugin_class(module)
        if PluginCls is None:
            raise PluginLoadError("包内未定义 Plugin 子类（应在 main.py 中定义）")

        # ---- 元信息：清单 > 类属性 > README/LICENSE 推断 ----
        manifest = pkg.manifest
        pname = str(manifest.get("name") or getattr(PluginCls, "name", "") or pkg.plugin_id)
        version = str(manifest.get("version") or getattr(PluginCls, "version", "0.0.0"))
        description = str(manifest.get("description")
                          or getattr(PluginCls, "description", "") or pkg.description)
        ptype = getattr(PluginCls, "plugin_type", PluginType.SYSTEM)

        # ---- 配置解析：清单默认值 < 管理员提供的 plugins.json ----
        cfg_cls = getattr(PluginCls, "Config", None)
        cfg_instance = None
        if isinstance(cfg_cls, type) and issubclass(cfg_cls, Config):
            values = dict(pkg.config_defaults())
            admin = dict(self._configs.get(pkg.plugin_id,
                                           self._configs.get(pname, {})))
            admin.pop("enabled", None)
            values.update(admin)
            cfg_instance = _resolve_config(cfg_cls, pkg.plugin_id, values)

        # ---- 实例化 ----
        if cfg_instance is not None:
            try:
                instance = PluginCls(config=cfg_instance)
            except TypeError:
                instance = PluginCls()
                instance.config = cfg_instance
        else:
            instance = PluginCls()

        meta = PluginMeta(
            name=pname,
            version=version,
            description=description,
            plugin_type=ptype,
            enabled=True,
            instance=instance,
            plugin_id=pkg.plugin_id,
            author=str(manifest.get("author", "")),
            license_name=pkg.license_name,
            homepage=str(manifest.get("homepage", "")),
            tags=list(manifest.get("tags") or []),
            requirements=pkg.requirements,
            package=pkg,
        )

        # ---- 注入上下文并调用 on_load（同步 / 异步均可）----
        instance._manager = self
        instance._meta = meta
        instance._package = pkg
        instance.name = pname
        token = current_plugin.set(meta)
        try:
            _maybe_await(instance.on_load())
        finally:
            current_plugin.reset(token)

        # 留一份「上一版可用源码」，供重载失败时回滚
        try:
            self._snapshots[pkg.plugin_id] = pkg.snapshot_source()
        except Exception as e:  # pragma: no cover - 快照失败不应影响加载
            logger.debug("插件 %s 源码快照失败：%s", pkg.plugin_id, e)

        self._instances[pkg.plugin_id] = instance
        self._packages[pkg.plugin_id] = pkg
        self._metas[pkg.plugin_id] = meta
        _registry.register(meta)
        logger.info("插件已加载：%s v%s（id=%s, 形态=%s, type=%s, license=%s）",
                    pname, version, pkg.plugin_id, pkg.fmt,
                    getattr(ptype, "value", ptype), meta.license_name or "未声明")
        return instance

    @staticmethod
    def _find_plugin_class(module) -> Optional[type]:
        """从入口模块里挑出插件主类。

        优先取模块级 ``plugin_class`` / ``entry`` 指向的类；否则取唯一/首字母
        优先定义的 Plugin 子类；定义了 name 的类排在没有 name 的前面。
        """
        entry = getattr(module, "plugin_class", None) or getattr(module, "entry", None)
        if isinstance(entry, type) and issubclass(entry, _Plugin):
            return entry
        candidates = [
            (n, o) for n, o in vars(module).items()
            if isinstance(o, type) and issubclass(o, _Plugin)
            and o not in (_Plugin,)
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda x: (not getattr(x[1], "name", ""), x[0]))
        return candidates[0][1]

    # ------------------------------------------------------------------
    # 卸载 / 重载
    # ------------------------------------------------------------------
    def _locate(self, name: str) -> Optional[str]:
        """把显示名或 id 解析成内部 id。"""
        if name in self._instances:
            return name
        for pid, meta in self._metas.items():
            if meta.name == name:
                return pid
        return None

    def unload(self, name: str, purge: bool = True) -> bool:
        """卸载插件，调用 on_unload 并注销注册表。

        Args:
            purge: 是否同时清理 sys.modules（默认清理，使 reload 能拿到新代码）
        """
        pid = self._locate(name)
        if pid is None:
            return False
        instance = self._instances.pop(pid)
        pkg = self._packages.pop(pid, None)
        self._metas.pop(pid, None)

        try:
            _maybe_await(instance.on_unload())
        except Exception as e:  # pragma: no cover
            logger.exception("插件 %s 卸载时出错：%s", pid, e)

        _registry.unregister(pid)
        if purge and pkg is not None:
            pkg.purge_modules()
        logger.info("插件已卸载：%s", pid)
        return True

    def reload(self, name: str, rollback: bool = True) -> bool:
        """重载插件（卸载 → 清理模块缓存 → 重新加载）。

        新代码加载失败时默认**回滚**到上一个版本，避免一次语法错误就让插件
        从应用里彻底消失（热重载尤其依赖这个行为）。
        """
        pid = self._locate(name)
        if pid is None:
            return False
        pkg = self._packages.get(pid)
        if pkg is None:
            return False
        app = self.app
        self.unload(pid)

        # 重新走一遍加载路径，让磁盘上的最新代码生效
        try:
            self.load_package(open_package(pkg.path, plugin_id=pid))
            return True
        except Exception as e:
            logger.error("插件 %s 重载失败：%s", pid, e)
            if rollback:
                snap = self._snapshots.get(pid)
                if snap:
                    try:
                        self.load_package(package_from_snapshot(pid, snap))
                        logger.warning(
                            "插件 %s 已回滚到上一版源码（临时副本），磁盘上的新代码有错误",
                            pid)
                    except Exception as e2:
                        logger.error("插件 %s 回滚也失败：%s", pid, e2)
                else:  # 没有快照可回滚，至少把磁盘上的版本再试一次
                    try:
                        self.load_package(open_package(pkg.path, plugin_id=pid))
                    except Exception as e2:
                        logger.error("插件 %s 重新加载失败：%s", pid, e2)
            return False
        finally:
            self.app = app

    def unload_all(self) -> None:
        for pid in list(self._instances.keys()):
            self.unload(pid)

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def list_loaded(self) -> List[str]:
        return list(self._instances.keys())

    def get(self, name: str) -> Optional[Any]:
        pid = self._locate(name)
        return self._instances.get(pid) if pid else None

    def get_package(self, name: str) -> Optional[PluginPackage]:
        """取得插件的来源包（用于读取 README / 资源等）。"""
        pid = self._locate(name)
        return self._packages.get(pid) if pid else None

    def get_meta(self, name: str) -> Optional[PluginMeta]:
        pid = self._locate(name)
        return self._metas.get(pid) if pid else None

    def read_resource(self, name: str, member: str) -> bytes:
        """读取某个插件包内的资源文件（找不到抛 PluginError）。"""
        pkg = self.get_package(name)
        if pkg is None:
            raise PluginError(f"插件未加载：{name}")
        if not pkg.exists(member):
            raise PluginError(f"插件 {name} 内没有资源 {member}")
        return pkg.read_bytes(member)


_manager = PluginManager()


def get_plugin_manager() -> PluginManager:
    return _manager
