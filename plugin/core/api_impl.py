"""插件 API 面（共享实现）。

``plugin.sync.*`` 与 ``plugin.async.*`` 两个包的模块都从这里再导出，因此同一份
实现既能被同步调用、也能在异步语境下被 await（见 core.runtime.dual）。

提供：
    add_page / Wrappers / PageHandle          页面与接口注册、响应构造
    serve_assets                              把插件包内目录挂成静态路由
    NeedArgument / resolve_arg                请求级依赖注入
    UserInfo / resolve_user_info              当前登录用户信息抽象与解析
"""
from __future__ import annotations

import enum
import inspect
import logging
import mimetypes
import posixpath
from contextvars import ContextVar
from dataclasses import dataclass
from itertools import count
from typing import Any, Callable, Optional, Tuple

from quart import (Response, abort, jsonify as _qjsonify, make_response,
                   redirect as _qredirect, render_template, request, session)

from .runtime import dual, current_plugin
from .info import PluginMeta

logger = logging.getLogger("apiproxy.plugins")


# ============================================================================
# NeedArgument：请求级依赖注入
# ============================================================================

class NeedArgument(enum.Enum):
    """可被注入的请求级参数（声明顺序即 handler 形参顺序）。"""
    user_info = "user_info"   # UserInfo 实例
    username = "username"     # 当前登录用户名（str 或 None）
    is_admin = "is_admin"     # 是否管理员（bool）
    request = "request"       # quart.request
    session = "session"       # quart.session
    config = "config"         # 本插件配置实例
    plugin = "plugin"         # 本插件实例
    form = "form"             # 请求表单（ImmutableMultiDict）
    json = "json"             # 解析后的 JSON body（或 None）
    args = "args"             # query string 参数
    app = "app"               # Quart app 实例


# ============================================================================
# UserInfo：当前登录用户抽象
# ============================================================================

@dataclass
class UserInfo:
    """可见的当前用户信息（插件不应直接触达 session / DB）。"""
    username: Optional[str] = None
    uid: Optional[str] = None
    email: Optional[str] = None
    is_admin: bool = False
    is_authenticated: bool = False

    @property
    def is_guest(self) -> bool:
        return not self.is_authenticated

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "uid": self.uid,
            "email": self.email,
            "is_admin": self.is_admin,
            "is_authenticated": self.is_authenticated,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return (f"<UserInfo {self.username!r} admin={self.is_admin} "
                f"auth={self.is_authenticated}>")


_GUEST = UserInfo()


def guest() -> UserInfo:
    """返回一个共享的游客（未登录）实例。"""
    return _GUEST


async def resolve_user_info() -> UserInfo:
    """从当前请求上下文解析 UserInfo。

    无 session 时返回游客；有登录用户时补全管理员标志与基础档案。
    所有外部依赖（quart / APIProxy）均延迟导入，避免导入期拖入整个应用。
    """
    try:
        from quart import session as _sess
    except Exception:
        return _GUEST

    username = _sess.get("user")
    if not username:
        return _GUEST

    is_admin = False
    uid: Optional[str] = None
    email: Optional[str] = None

    try:
        from APIProxy.core_auth import _is_admin
        is_admin = bool(await _is_admin())
    except Exception:
        is_admin = False

    try:
        from APIProxy.core_db import async_db_query
        rows = await async_db_query(
            "SELECT uid, email FROM users WHERE user_name = ?", (username,)
        )
        if rows:
            uid = rows[0].get("uid")
            email = rows[0].get("email")
    except Exception:
        pass

    return UserInfo(
        username=username,
        uid=uid,
        email=email,
        is_admin=is_admin,
        is_authenticated=True,
    )


# ============================================================================
# 解析器：NeedArgument -> 实际值
# ============================================================================

async def _a_user_info(p, m):
    return await resolve_user_info()

async def _a_username(p, m):
    return session.get("user")

async def _a_is_admin(p, m):
    try:
        from APIProxy.core_auth import _is_admin
        return bool(await _is_admin())
    except Exception:
        return False

async def _a_request(p, m):
    return request

async def _a_session(p, m):
    return session

async def _a_config(p, m):
    return p.instance.config if p else None

async def _a_plugin(p, m):
    return p.instance if p else None

async def _a_form(p, m):
    return await request.form

async def _a_json(p, m):
    return await request.get_json(silent=True)

async def _a_args(p, m):
    return request.args

async def _a_app(p, m):
    return m.app


_RESOLVERS = {
    NeedArgument.user_info: _a_user_info,
    NeedArgument.username: _a_username,
    NeedArgument.is_admin: _a_is_admin,
    NeedArgument.request: _a_request,
    NeedArgument.session: _a_session,
    NeedArgument.config: _a_config,
    NeedArgument.plugin: _a_plugin,
    NeedArgument.form: _a_form,
    NeedArgument.json: _a_json,
    NeedArgument.args: _a_args,
    NeedArgument.app: _a_app,
}


async def resolve_arg(need: NeedArgument, plugin, mgr) -> Any:
    """按 NeedArgument 解析出单个参数值。"""
    resolver = _RESOLVERS.get(need)
    if resolver is None:
        raise ValueError(f"未知的 NeedArgument: {need!r}")
    return await resolver(plugin, mgr)


# ============================================================================
# add_page：路由注册
# ============================================================================

_counter = count(1)


def _new_endpoint(pname: Optional[str]) -> str:
    return f"plugin_{(pname or 'anon')}_{next(_counter)}"


async def _add_page_impl(rule: str,
                        handler: Callable,
                        args: Tuple[NeedArgument, ...] = (),
                        methods: Tuple[str, ...] = ("GET",),
                        endpoint: Optional[str] = None,
                        login_required: bool = False) -> "PageHandle":
    """注册一个路由，返回 PageHandle 供后续卸载。"""
    from .manager import get_plugin_manager

    mgr = get_plugin_manager()
    app = mgr.app
    if app is None:
        raise RuntimeError("插件应用尚未初始化（app 未设置），无法注册路由")

    plugin = current_plugin.get()
    rule = rule.strip()
    ep = endpoint or _new_endpoint(plugin.name if plugin else None)

    async def _view(*a, **kw):
        if login_required and not session.get("user"):
            return _jsonify({"error": "unauthorized"}), 401
        resolved = []
        for need in args:
            resolved.append(await resolve_arg(need, plugin, mgr))
        result = handler(*resolved)
        if inspect.iscoroutine(result):
            result = await result
        return result

    app.add_url_rule(rule, ep, _view, methods=list(methods))
    return PageHandle(mgr, ep, rule)


# 同步可 call / 异步可 await
add_page = dual(_add_page_impl)


# ============================================================================
# serve_assets：把插件包内目录挂成静态路由
# ============================================================================

async def _serve_assets_impl(rule_prefix: str,
                             subdir: str = "assets",
                             endpoint: Optional[str] = None) -> "PageHandle":
    """把当前插件包里的某个目录暴露成静态文件路由。

    例：``serve_assets("/demo", "assets")`` 之后，请求 ``/demo/app.js``
    会返回包内 ``assets/app.js``。目录形态和 zip 形态都能工作 —— 因为读取
    统一走 PluginPackage 的成员 IO，zip 形态无需解压。
    """
    from .manager import get_plugin_manager

    mgr = get_plugin_manager()
    app = mgr.app
    if app is None:
        raise RuntimeError("插件应用尚未初始化（app 未设置），无法注册路由")

    plugin = current_plugin.get()
    pkg = getattr(plugin, "package", None) if plugin else None
    if pkg is None:
        raise RuntimeError("当前没有加载中的插件包，serve_assets 只能在插件内部调用")

    prefix = "/" + rule_prefix.strip().strip("/")
    rule = f"{prefix}/<path:filename>"
    ep = endpoint or _new_endpoint(plugin.name if plugin else None) + "_assets"
    base = subdir.strip("/") if subdir else ""

    async def _view(filename: str):
        # 防目录穿越
        safe = posixpath.normpath(filename).lstrip("/")
        if safe.startswith("..") or ".." in safe.split("/"):
            abort(404)
        member = f"{base}/{safe}" if base else safe
        if not pkg.exists(member):
            abort(404)
        ctype = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        return Response(pkg.read_bytes(member), mimetype=ctype)

    app.add_url_rule(rule, ep, _view, methods=["GET"])
    return PageHandle(mgr, ep, rule)


# 同样既可 call 也可 await
serve_assets = dual(_serve_assets_impl)


# ============================================================================
# Wrappers：响应构造工具
# ============================================================================

# ---------------------------------------------------------------------------
# Wrappers：响应构造工具
#
# 设计要点： jsonify / html / text / redirect 走「同步实现 + 可 await 返回值」
# 路线，而不是抽象的双模协程。原因：Quart 的 current_app 等是 contextvar，
# 若靠另起线程执行协程，必须复制上下文才能保证不报「Not within an app
# context」，而 json 响应是每请求热路径，开线程代价过高。这里返回的对象本身
# 就是合法 Response（可直接 return），又实现了 __await__（可 await），一举两得。
# ---------------------------------------------------------------------------

class _DualResponse(Response):
    """既是合法的 Quart Response（可直接 return），也可 await（await 得到自身）。"""

    def __await__(self):
        async def _identity():
            return self
        return _identity().__await__()


class _DualStr(str):
    """既是 str（可直接 return 由 Quart 包成 Response），也可 await。"""

    def __await__(self):
        async def _identity():
            return str(self)
        return _identity().__await__()


def _identity_coro(value):
    async def _inner():
        return value
    return _inner()


# 动态生成的「可 await 子类」缓存，避免每请求重复建类
_dual_cls_cache: dict = {}


def _dual_response(resp: Response) -> Response:
    """把已有 Response 实例升格为「可 await」的响应。

    不复制内容（Quart 的 get_data() 本身是协程，没法同步取 body），
    只把实例的类换成动态生成的子类，该子类额外带 __await__。
    这样：直接 return 它 → 是合法 Response；await 它 → 得到同一个 Response。
    """
    if hasattr(type(resp), "__await__"):
        return resp
    cls = type(resp)
    sub = _dual_cls_cache.get(cls)
    if sub is None:
        sub = type(f"Awaitable{cls.__name__}", (cls,),
                   {"__await__": lambda self: _identity_coro(self).__await__()})
        _dual_cls_cache[cls] = sub
    resp.__class__ = sub
    return resp


def _jsonify(obj: Any, **kwargs):
    try:
        resp = _qjsonify(obj, **kwargs)
    except (TypeError, ValueError):
        if hasattr(obj, "to_dict"):
            resp = _qjsonify(obj.to_dict(), **kwargs)
        else:
            raise
    return _dual_response(resp)


def _html(body: str, status: int = 200) -> Response:
    return _DualResponse(body, status=status, mimetype="text/html")


def _text(body: str, status: int = 200) -> Response:
    return _DualResponse(body, status=status, mimetype="text/plain")


def _redirect(location: str, code: int = 302):
    return _dual_response(_qredirect(location, code=code))


def _abort(*a, **k):
    abort(*a, **k)


async def _render_template(*a, **k):
    return _DualStr(await render_template(*a, **k))


async def _make_response(*a, **k):
    res = make_response(*a, **k)
    if inspect.isawaitable(res):
        res = await res
    return _dual_response(res)


class _Wrappers:
    """命名空间；属性以实例属性方式挂载，避免被当成绑定方法。

    jsonify / html / text / redirect / abort 是同步实现（返回可 await 结果），
    render_template / make_response 走 dual（需要事件循环，且带上下文传播）。
    """
    pass


Wrappers = _Wrappers()
Wrappers.jsonify = _jsonify
Wrappers.html = _html
Wrappers.text = _text
Wrappers.redirect = _redirect
Wrappers.abort = _abort
Wrappers.render_template = dual(_render_template)
Wrappers.make_response = dual(_make_response)


# ============================================================================
# PageHandle：路由句柄（可反向卸载）
# ============================================================================

class PageHandle:
    """add_page 的返回对象，持有路由端点信息，可反向卸载。"""

    def __init__(self, mgr, endpoint: str, rule: str):
        self._mgr = mgr
        self.endpoint = endpoint
        self.rule = rule

    @staticmethod
    def _unbind(url_map, rule) -> None:
        """从底层匹配结构中摘除 rule。

        Werkzeug 没有公开的 remove API。新版（>=2.2）把规则编译进
        StateMachineMatcher 的状态树，需要递归遍历状态节点把 rule 摘掉；
        旧版则直接维护 ``_rules`` 列表。两种都兼容处理。
        """
        # 旧版 werkzeug：直接操作列表（新版里 _rules 是只读 property，此处为 no-op）
        rules_list = getattr(url_map, "_rules", None)
        if isinstance(rules_list, list):
            for i, r in enumerate(list(rules_list)):
                if r is rule:
                    rules_list.pop(i)
                    break

        # 新版 werkzeug：规则挂在状态树叶子节点的 rules 列表里
        root = getattr(getattr(url_map, "_matcher", None), "_root", None)
        if root is None:
            return

        seen: set = set()

        def walk(state) -> None:
            if state is None or id(state) in seen:
                return
            seen.add(id(state))
            rs = getattr(state, "rules", None)
            if isinstance(rs, list):
                for i, r in enumerate(rs):
                    if r is rule:
                        del rs[i]
                        break
            for child in list(getattr(state, "static", {}).values()):
                walk(child)
            for _part, child in list(getattr(state, "dynamic", [])):
                walk(child)

        walk(root)

    def close(self) -> bool:
        """从应用中移除该路由（同时摘掉 view function 与 URL 匹配规则）。"""
        app = self._mgr.app
        if app is None:
            return False
        try:
            app.view_functions.pop(self.endpoint, None)
            url_map = getattr(app, "url_map", None)
            if url_map is None:
                return False

            targets = [r for r in url_map.iter_rules()
                       if r.endpoint == self.endpoint]
            if not targets:
                return False

            by_ep = getattr(url_map, "_rules_by_endpoint", None)
            if isinstance(by_ep, dict):
                by_ep.pop(self.endpoint, None)

            for rule in targets:
                self._unbind(url_map, rule)

            # 标记需要重建，并触发 update 刷新匹配器排序
            try:
                setattr(url_map, "_remap", True)
            except Exception:  # pragma: no cover - 只读属性时忽略
                pass
            if hasattr(url_map, "update"):
                url_map.update()
            return True
        except Exception as e:  # pragma: no cover - 防御性
            logger.warning("关闭页面句柄失败 %s: %s", self.endpoint, e)
            return False

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PageHandle {self.rule} ({self.endpoint})>"
