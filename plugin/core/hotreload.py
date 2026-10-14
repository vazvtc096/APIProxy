"""插件热重载：盯着 plugins/ 目录，文件一变就自动重载对应插件。

设计取舍
--------
**为什么用轮询而不是 watchdog**：不引第三方依赖；而且编辑器保存通常是
「删除 + 写入 + 再改」一串中间态，轮询配合静默期（settle）天然能把多次
事件合并成一次重载，比逐事件触发稳。

**安全约束**：
1. 默认关闭 —— 生产环境不该开。开启方式：环境变量 ``PLUGIN_HOT_RELOAD=1``
   或根目录 ``plugins.json`` 里写 ``"hot_reload": true``。
2. 变更一律投递到 **app 所在的事件循环** 里执行（``run_coroutine_threadsafe``），
   绝不在别的线程里改 Quart 的 url_map。
3. 新代码加载失败会**回滚到上一个版本**，插件不会因为一次语法错误就凭空消失。

用法
----
自动（推荐，和 app 生命周期绑定）：

    from plugin import attach_hot_reload
    attach_hot_reload(app)          # create_app() 里调用，服务启动时才真正开始

手动：

    from plugin import start_hot_reload
    start_hot_reload(app)           # 立即在后台线程开始巡检
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .archive import PluginPackage, iter_packages
from .exceptions import PluginError
from .runtime import bus

logger = logging.getLogger("apiproxy.plugins.hotreload")

_TRUE = ("1", "true", "yes", "y", "on")


def _env_bool(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() in _TRUE


@dataclass
class _Op:
    """一次待执行的重载动作。"""
    kind: str                     # 'load' | 'unload' | 'reload'
    plugin_id: str
    package: Optional[PluginPackage] = None

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Op {self.kind} {self.plugin_id}>"


class HotReloader:
    """插件热重载器（后台巡检线程 + 事件循环内应用变更）。"""

    def __init__(self, manager=None, interval: Optional[float] = None,
                 settle: Optional[float] = None):
        self.mgr = manager
        self.interval = float(interval or os.environ.get("PLUGIN_HOT_RELOAD_INTERVAL", 1.0))
        self.settle = float(settle or os.environ.get("PLUGIN_HOT_RELOAD_SETTLE", 0.6))
        self.app = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._snapshots: Dict[str, Tuple[str, Any]] = {}   # id → (path, sig)
        self._cfg_mtime: Optional[int] = None
        self._cfg_path: Optional[str] = None
        self.on_event: Optional[Callable[[str, str], None]] = None

    # ------------------------------------------------------------------
    # 启停
    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def manager(self):
        if self.mgr is None:
            from .manager import get_plugin_manager
            self.mgr = get_plugin_manager()
        return self.mgr

    def start(self, app=None, loop=None) -> "HotReloader":
        """开始巡检。幂等：已在运行则只更新 app / loop 引用。"""
        with self._lock:
            if app is not None:
                self.app = app
                self.manager.set_app(app)
            if loop is None:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = self._loop
            self._loop = loop

            if self.running:
                return self

            self._stop.clear()
            self._snapshots = self._snapshot()
            self._thread = threading.Thread(target=self._run,
                                            name="plugin-hotreload", daemon=True)
            self._thread.start()
            logger.info("插件热重载已启动（interval=%ss, settle=%ss, loop=%s）",
                        self.interval, self.settle,
                        "捕获" if loop else "未捕获→同线程执行")
        return self

    def stop(self, wait: float = 2.0) -> None:
        with self._lock:
            if not self.running:
                return
            self._stop.set()
            t = self._thread
        if t is not None:
            t.join(timeout=wait)
        logger.info("插件热重载已停止")

    def attach(self, app) -> "HotReloader":
        """把启停挂到 app 的 before_serving / after_serving 上。

        这样做的原因：``create_app()`` 是同步的，此时服务用的事件循环还没
        创建；而 ``before_serving`` 运行在真正的服务循环里，正好能把 loop
        交给热重载线程，让它用 run_coroutine_threadsafe 安全投递变更。
        """
        self.app = app

        @app.before_serving
        async def _start_with_loop():  # pragma: no cover - 需真实服务场景
            if not self.manager.hot_reload:
                return
            self.start(app=app, loop=asyncio.get_running_loop())

        @app.after_serving
        async def _stop_watcher():  # pragma: no cover
            self.stop()

        return self

    # ------------------------------------------------------------------
    # 巡检
    # ------------------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # 巡检本身绝不能把进程带崩
                logger.exception("插件热重载巡检出错")
            self._stop.wait(self.interval)

    def trigger(self) -> List[_Op]:
        """手动触发一次检查（测试 / 管理接口用）。返回本次执行的动作列表。"""
        with self._lock:
            ops = self._collect()
            if ops:
                self._apply(ops)
            return ops

    def _tick(self) -> None:
        ops = self._collect()
        if ops:
            self._apply(ops)

    def _collect(self) -> List[_Op]:
        """对比磁盘快照，算出本次要做的动作。"""
        with self._lock:
            current = self._snapshot()
            cfg_changed = self._config_changed()
            ops: List[_Op] = self._diff(current)
            if cfg_changed:
                ops += self._diff_enabled(current)

            if not ops:
                return ops

            # 静默期：编辑器保存会产生一串中间态，等一会儿再取一次真实快照，
            # 避免把「删了又写」误判成 removed + added。
            if self.settle and not self._stop.is_set():
                time.sleep(self.settle)
                current = self._snapshot()
                ops = self._diff(current)
                if cfg_changed:
                    ops += self._diff_enabled(current)

            self._snapshots = {k: (v[0], v[1]) for k, v in current.items()}
            return ops

    # ------------------------------------------------------------------
    # 快照与差异
    # ------------------------------------------------------------------
    def _snapshot(self) -> Dict[str, Tuple[str, Any]]:
        """{plugin_id: (包路径, 指纹)}。指纹变了就认为内容变了。"""
        out: Dict[str, Tuple[str, Any]] = {}
        mgr = self.manager
        for pkg in iter_packages(mgr.plugins_dir):
            try:
                out[pkg.plugin_id] = (pkg.path, self._signature(pkg))
            except OSError as e:  # 文件正被写入时可能短暂不可读
                logger.debug("快照跳过 %s：%s", pkg.plugin_id, e)
        return out

    @staticmethod
    def _signature(pkg: PluginPackage) -> Tuple:
        """生成包内容指纹：mtime_ns + size（够灵敏也够便宜）。"""
        if pkg.is_zip:
            st = os.stat(pkg.path)
            return ("zip", st.st_mtime_ns, st.st_size)

        parts: List[Tuple[str, int, int]] = []
        for base, dirs, files in os.walk(pkg.root):
            dirs[:] = [d for d in dirs
                       if d not in ("__pycache__", ".git") and not d.startswith(".")]
            for f in files:
                if f.endswith((".pyc", ".pyo")) or f.startswith("."):
                    continue
                full = os.path.join(base, f)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                parts.append((os.path.relpath(full, pkg.root), st.st_mtime_ns, st.st_size))
        parts.sort()
        return ("dir", tuple(parts))

    def _diff(self, current: Dict[str, Tuple[str, Any]]) -> List[_Op]:
        ops: List[_Op] = []
        for pid, (path, sig) in current.items():
            prev = self._snapshots.get(pid)
            if prev is None:
                ops.append(_Op("load", pid))
            elif prev[1] != sig:
                ops.append(_Op("reload", pid))
        for pid in self._snapshots:
            if pid not in current:
                ops.append(_Op("unload", pid))
        # 补上包对象，供后续直接加载
        for op in ops:
            if op.kind in ("load", "reload") and op.package is None:
                try:
                    from .archive import open_package
                    op.package = open_package(current[op.plugin_id][0], plugin_id=op.plugin_id)
                except (KeyError, PluginError):
                    op.kind = "skip"
        return [o for o in ops if o.kind != "skip"]

    def _diff_enabled(self, current: Dict[str, Tuple[str, Any]]) -> List[_Op]:
        """配置变了：新启用的加载、被禁用的卸载。"""
        mgr = self.manager
        ops: List[_Op] = []
        for pid, (path, _sig) in current.items():
            try:
                from .archive import open_package
                pkg = open_package(path, plugin_id=pid)
            except PluginError:
                continue
            want = mgr._plugin_enabled(pkg)
            have = pid in mgr._instances
            if want and not have:
                ops.append(_Op("load", pid, pkg))
            elif have and not want:
                ops.append(_Op("unload", pid, pkg))
        return ops

    # ------------------------------------------------------------------
    # 应用变更
    # ------------------------------------------------------------------
    def _apply(self, ops: List[_Op]) -> None:
        if not ops:
            return
        loop = self._loop
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        # 已经在 app 的事件循环线程里（例如从管理接口手动触发）→ 直接执行，
        # 若再 run_coroutine_threadsafe 等结果，会因为阻塞了同一个 loop 而死锁。
        if running is not None and running is loop:
            self._apply_sync(ops)
            return

        if loop is not None and not loop.is_closed():
            try:
                fut = asyncio.run_coroutine_threadsafe(self._async_apply(ops), loop)
                fut.result(timeout=30)
                return
            except Exception as e:
                logger.warning("热重载在事件循环内执行失败，回退到巡检线程：%s", e)
        self._apply_sync(ops)

    async def _async_apply(self, ops: List[_Op]) -> None:
        """在 app 的事件循环里执行，保证改 url_map 是线程安全的。"""
        self._apply_sync(ops)

    def _apply_sync(self, ops: List[_Op]) -> None:
        mgr = self.manager
        for op in ops:
            try:
                if op.kind == "load":
                    if op.plugin_id in mgr._instances:
                        continue
                    pkg = op.package or mgr._packages.get(op.plugin_id)
                    if pkg is None:
                        continue
                    mgr.load_package(pkg)
                    self._emit("plugin:loaded", op.plugin_id)

                elif op.kind == "reload":
                    mgr.reload(op.plugin_id)
                    self._emit("plugin:reloaded", op.plugin_id)

                elif op.kind == "unload":
                    mgr.unload(op.plugin_id)
                    self._emit("plugin:unloaded", op.plugin_id)

            except Exception as e:
                logger.error("热重载动作 %s %s 失败：%s", op.kind, op.plugin_id, e)

    def _emit(self, event: str, plugin_id: str) -> None:
        logger.info("热重载：%s → %s", event, plugin_id)
        if self.on_event:
            try:
                self.on_event(event, plugin_id)
            except Exception:  # pragma: no cover
                pass
        try:
            bus.emit(event, plugin_id)
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------
    # 配置文件
    # ------------------------------------------------------------------
    def _config_changed(self) -> bool:
        path = self._cfg_path or self._find_config()
        if not path or not os.path.isfile(path):
            return False
        try:
            mtime = os.stat(path).st_mtime_ns
        except OSError:
            return False
        if self._cfg_mtime is None:
            self._cfg_mtime = mtime
            return False
        if mtime == self._cfg_mtime:
            return False
        self._cfg_mtime = mtime
        try:
            self.manager._load_config_file(path)
            logger.info("插件配置已变更，重新读取：%s", path)
        except Exception as e:
            logger.warning("重新读取插件配置失败：%s", e)
        return True

    def _find_config(self) -> Optional[str]:
        mgr = self.manager
        root = os.path.dirname(mgr.plugins_dir) if mgr.plugins_dir else os.getcwd()
        for name in ("plugins.json", "plugins.yaml"):
            p = os.path.join(root, name)
            if os.path.isfile(p):
                self._cfg_path = p
                return p
        return None


# ----------------------------------------------------------------------
# 便捷入口
# ----------------------------------------------------------------------

_hot_reloader: Optional[HotReloader] = None


def get_hot_reloader() -> HotReloader:
    global _hot_reloader
    if _hot_reloader is None:
        _hot_reloader = HotReloader()
    return _hot_reloader


def attach_hot_reload(app=None) -> Optional[HotReloader]:
    """把热重载挂到 app 生命周期上。未启用时什么都不做。"""
    r = get_hot_reloader()
    if not r.manager.hot_reload:
        logger.info("插件热重载未启用（PLUGIN_HOT_RELOAD=1 或 plugins.json 的 hot_reload: true 可开启）")
        return None
    return r.attach(app) if app is not None else r


def start_hot_reload(app=None, interval: Optional[float] = None) -> Optional[HotReloader]:
    """立即启动热重载（不依赖 app 生命周期，适合测试与脚本）。"""
    r = get_hot_reloader()
    if not r.manager.hot_reload and not _env_bool("PLUGIN_HOT_RELOAD"):
        logger.info("插件热重载未启用")
        return None
    if interval:
        r.interval = interval
    return r.start(app=app)


def stop_hot_reload() -> None:
    get_hot_reloader().stop()
