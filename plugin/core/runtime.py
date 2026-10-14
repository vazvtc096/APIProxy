"""插件运行时基础设施：日志、事件总线、双模函数、当前插件上下文。

双模函数（dual）是这套插件系统的关键：同一个 API 函数既能被「同步调用」
（``add_page(...)`` 直接拿结果），也能在异步语境下被 ``await``
（``await add_page(...)``），判定依据是调用方是否处于协程函数体内。
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import sys
import threading
from contextvars import ContextVar, copy_context
from typing import Any, Awaitable, Callable, TypeVar

R = TypeVar("R")

# inspect.CO_COROUTINE 的数值（协程函数的 code 标志位）
_CO_COROUTINE = 0x80

logger = logging.getLogger("apiproxy.plugins")


def get_logger(name: str = "plugin") -> logging.Logger:
    """返回某个插件专属 logger。"""
    return logging.getLogger(f"apiproxy.plugins.{name}")


class EventBus:
    """极简进程内事件总线，用于插件间解耦通信。

    ``emit`` 同时兼容同步处理器与异步处理器：若处理器返回可 await 对象，
    则在新线程的临时事件循环里跑完（避免阻塞当前协程）。
    """

    def __init__(self) -> None:
        self._handlers: dict = {}

    def on(self, event: str, handler: Callable) -> None:
        self._handlers.setdefault(event, []).append(handler)

    def off(self, event: str, handler: Callable) -> None:
        subs = self._handlers.get(event, [])
        if handler in subs:
            subs.remove(handler)

    def emit(self, event: str, *args: Any, **kwargs: Any) -> None:
        for h in list(self._handlers.get(event, [])):
            try:
                res = h(*args, **kwargs)
                if inspect.isawaitable(res):
                    _run_in_new_thread(res)
            except Exception as e:  # pragma: no cover - 单订阅者异常不扩散
                logger.warning("事件 %s 的处理器异常：%s", event, e)


# 全局事件总线单例
bus = EventBus()


# 当前正在加载 / 处理请求的插件元信息（由管理器设置，add_page 据此归属路由）
current_plugin: ContextVar = ContextVar("apiproxy_current_plugin", default=None)


def get_current_plugin():
    return current_plugin.get()


def is_async_context() -> bool:
    """调用方是否处于协程函数体内（向上两层取调用者帧）。"""
    try:
        frame = sys._getframe(2)
    except ValueError:  # pragma: no cover
        return False
    return bool(frame.f_code.co_flags & _CO_COROUTINE)


def _run_in_new_thread(coro: Awaitable[R]) -> R:
    """在独立线程里跑一个全新的事件循环，把协程跑完并返回结果。

    用于「已有事件循环在运行、但当前不在协程内」时同步取得异步结果，
    避免 asyncio.run 报「loop already running」。

    关键：先 copy_context() 把当前上下文（app/request context、current_plugin
    等 contextvar）带进新线程，否则协程里读到的会是空上下文——Quart 的
    current_app 就会报「Not within an app context」。
    """
    ctx = copy_context()
    box: dict = {}
    ev = threading.Event()

    def runner() -> None:
        loop = asyncio.new_event_loop()
        try:
            box["r"] = ctx.run(loop.run_until_complete, coro)
        except BaseException as e:  # noqa: BLE001 - 把异常传回主线程
            box["e"] = e
        finally:
            loop.close()
            ev.set()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join()
    if "e" in box:
        raise box["e"]
    return box["r"]  # type: ignore[return-value]


def run_sync(coro: Awaitable[R]) -> R:
    """把协程跑完并返回结果。

    - 当前没有运行中的事件循环：直接 ``asyncio.run``。
    - 有运行中循环但不在协程内：开新线程跑（防死锁）。
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    return _run_in_new_thread(coro)


def dual(fn: Callable[..., Awaitable[R]]) -> Callable[..., R]:
    """将 async 实现 ``fn`` 变成「同步可 call / 异步可 await」的双模函数。

    判定规则：检测调用方是否处于协程函数体内
    （``sys._getframe(1).f_code.co_flags & CO_COROUTINE``）。
    若是 → 返回可被 await 的协程；否则 → 同步执行并返回结果。

    这样插件作者无论是继承 ``SyncPlugin``（方法为普通 ``def``）
    还是 ``AsyncPlugin``（方法为 ``async def``），都能用同一套 API，
    调用方语境自动决定走同步还是异步分支。
    """
    if inspect.iscoroutinefunction(fn):
        impl = fn
    else:
        async def impl(*a, **k):
            return fn(*a, **k)

    @functools.wraps(fn)
    def outer(*args, **kwargs):
        frame = sys._getframe(1)
        if frame.f_code.co_flags & _CO_COROUTINE:
            return impl(*args, **kwargs)
        return run_sync(impl(*args, **kwargs))

    return outer
