"""中间件注册：在 Quart app 上注册全局 before_request / after_request 处理器。

包括：WAF 规则检查、CSRF 保护、强制改密拦截、安全响应头、CORS、CSRF 注入。
"""
import ipaddress
import json
import logging
import re
import secrets
import time
from urllib.parse import urlparse
from quart import request, session, jsonify, g

from ..app import app
from ..core import (
    _get_csrf_token, _validate_csrf_token, _get_client_ip, _get_user_agent,
    async_db_query, _whitelist_bypass, _validate_session,
    EXEMPT_CSRF_METHODS, EXEMPT_CSRF_PATHS, is_csrf_exempt_path, _CSRF_PATCH_JS,
)
from ..configs import SSL_ENABLED, HSTS_ENABLED, HSTS_MAX_AGE, HSTS_INCLUDE_SUBDOMAINS, HSTS_PRELOAD, STATIC_CACHE_MAX_AGE
from .. import waf as _waf
from .. import ids_ips as _ids
from .. import web_filter as _wf
from .. import bastion as _bastion
from .. import seq_anomaly as _seq
from .. import ja3 as _ja3
from .. import honeypot as _honeypot
from .. import ja3_threat as _ja3threat
from .. import bot_score as _botscore
from .. import configs as _seq_configs


# 事件委托脚本：替代内联 onclick/oninput 等内联事件处理器（CSP 移除 'unsafe-inline' 后，
# 内联事件处理器会被浏览器拒绝执行）。本脚本会被注入到**每一个** HTML 响应，是全局唯一的
# 权威实现（window.__actionDelegationInstalled 幂等标记）；templates/_sidebar.html 里的
# 同名实现已降级为「未被注入时的兜底」，运行时检测到本标记即跳过，避免一次点击被执行两遍。
#
# 约定：
#   data-action="fn"                          → click 时调用 window.fn()（this=元素）
#   data-action="fn" data-args="a\x01b"       → 传参 window.fn(a, b)
#   data-action="fn" data-on="input|..."      → 指定事件类型（默认 click）
#   data-arg-this                             → 追加元素本身作为参数（排在 data-args 之后）
#   data-arg-value                            → 追加元素 .value 作为参数
#   data-arg-event                            → 追加事件对象作为参数（排在最前）
#   data-then="fn2" data-then-args="a"        → 主 action 之后调用 fn2(a)；主 action 返回
#                                               Promise 时等其 settle 后再调用
#   data-stop                                 → stopPropagation（原 onclick="event.stopPropagation()"）
#   data-prevent                              → preventDefault（原 onsubmit="return false"）
#   data-nav="/path"                          → 点击跳转（替代 onclick="location.href='...'"）
#
# 参数顺序（与既有模板写法一致，勿改）：[event?] ...data-args [el?] [el.value?]
# 参数解析优先级：JSON > \x01 分隔 > 逗号分隔 > 单值；每项 trim 后：
#   1. 剥离外层配对单引号（兼容历史写法 data-args="'${id}'"，字面引号不应成为参数的一部分）
#   2. 仅 "true"/"false" 还原为布尔——否则 data-args="'id'\x01${flag}" 会拿到字符串
#      "false"，而 "false" 是 truthy，导致 !enabled 永远为 false（钩子无法启用）。
#      其余值一律保持字符串，避免把 "0123" 这类 ID 误转成数字。
_EVENT_DELEGATION_JS = """<script>
(function () {
  if (window.__actionDelegationInstalled) return;
  window.__actionDelegationInstalled = true;

  function parseArgs(str) {
    if (!str) return [];
    try {
      var p = JSON.parse(str);
      return Array.isArray(p) ? p : [p];
    } catch (e) { /* 非 JSON，按分隔符回退解析 */ }
    var parts;
    if (str.indexOf('\\u0001') !== -1) parts = str.split('\\u0001');
    else if (str.indexOf(',') !== -1) parts = str.split(',');
    else parts = [str];
    return parts.map(function (s) {
      s = String(s).trim();
      if (s.length >= 2 && s.charAt(0) === "'" && s.charAt(s.length - 1) === "'") s = s.slice(1, -1);
      if (s === 'true') return true;
      if (s === 'false') return false;
      return s;
    });
  }

  function run(el, e, action) {
    if (!action) return undefined;
    var fn = window[action];
    if (typeof fn !== 'function') {
      console.warn('[data-action] 函数不存在:', action);
      return undefined;
    }
    var args = [];
    if (el.hasAttribute('data-arg-event')) args.push(e);
    if (el.hasAttribute('data-args')) args = args.concat(parseArgs(el.getAttribute('data-args')));
    if (el.hasAttribute('data-arg-this')) args.push(el);
    if (el.hasAttribute('data-arg-value')) args.push(el.value);
    var r = fn.apply(el, args);
    var thenAction = el.getAttribute('data-then');
    if (thenAction) {
      var fn2 = window[thenAction];
      if (typeof fn2 === 'function') {
        var a2 = parseArgs(el.getAttribute('data-then-args') || '');
        var callThen = function () { fn2.apply(el, a2); };
        if (r && typeof r.then === 'function') r.then(callThen, callThen);
        else callThen();
      }
    }
    return r;
  }

  function dispatch(e) {
    if (!e.target || typeof e.target.closest !== 'function') return;
    // 多事件绑定：data-on-<event>="action"（同一元素可绑定多个不同事件）
    var el = e.target.closest('[data-on-' + e.type + ']');
    var action = el ? el.getAttribute('data-on-' + e.type) : null;
    // 单事件便捷写法：data-action + data-on
    if (!action) {
      el = e.target.closest('[data-action]');
      if (el) {
        var on = el.getAttribute('data-on');
        if (on === e.type || (!on && e.type === 'click')) {
          action = el.getAttribute('data-action');
        } else {
          el = null;
        }
      }
    }
    if (!el || !action) return;
    if (el.hasAttribute('data-stop')) e.stopPropagation();
    var r = run(el, e, action);
    // 原生可提交/可跳转元素默认阻止默认行为，避免 data-action 触发后页面意外刷新或跳转
    var formish = el.tagName === 'A' || el.tagName === 'BUTTON' || el.tagName === 'INPUT' ||
                  el.tagName === 'FORM' || !!el.closest('form');
    if (el.hasAttribute('data-prevent') || r === false || formish) e.preventDefault();
  }

  document.addEventListener('click', function (e) {
    if (!e.target || typeof e.target.closest !== 'function') return;
    var nav = e.target.closest('[data-nav]');
    if (nav) {
      if (nav.hasAttribute('data-stop')) e.stopPropagation();
      window.location.href = nav.getAttribute('data-nav');
      return;
    }
    dispatch(e);
  });
  ['input', 'change', 'keydown', 'submit', 'contextmenu',
   'touchend', 'touchcancel', 'touchstart', 'mouseup', 'mouseleave',
   'mousedown'].forEach(function (t) {
    document.addEventListener(t, dispatch);
  });
})();
</script>"""


# 全站主题（个性化）注入 —— 亮暗完全由 JS 调节（CSR 式）：
#   服务端不做任何主题判断、不注入任何主题 <style>。JS 是唯一控制器：
#   状态(localStorage) -> 决策(bootstrap 脚本) -> 挂载(adoptedStyleSheets) 全在客户端。
#   _THEME_DARK_CSS     —— 暗色样式源文本（内嵌进 bootstrap 脚本，由 JS 挂载/摘除）
#   _THEME_BOOTSTRAP_JS —— <head> 内同步执行：解析出 light/dark 后，
#                          以 JS 持有的 CSSStyleSheet（document.adoptedStyleSheets）挂载暗色样式，
#                          同时设置 html[data-theme]（图表与模板内暗色规则依赖此属性）。
#                          首帧绘制前完成，无闪白；浅色时文档中不存在任何暗色 CSS。
#   _THEME_UI_JS        —— body 末尾执行，创建顶栏主题切换按钮（浅色/深色/跟随系统循环）
#   _THEME_CHARTS_JS    —— Chart.js 暗色 re-theme（读 data-theme 属性）
#   _PROGRESS_HTML      —— 页面顶部加载进度条（head 内即启动，load 事件完成收尾）
_THEME_DARK_CSS = """
  /* ===== 暗色主题样式源文本（由 _THEME_BOOTSTRAP_JS 挂载/摘除，勿在服务端注入）===== */
  html[data-theme="dark"] { color-scheme: dark; }
  html[data-theme="dark"] body {
    background: #0b0f19 !important;
    background-image: none !important;
    color: #e6ebf4 !important;
  }
  /* 面板容器统一深色 */
  html[data-theme="dark"] .navbar,
  html[data-theme="dark"] .sidebar,
  html[data-theme="dark"] .card,
  html[data-theme="dark"] .table-card,
  html[data-theme="dark"] .chart-card,
  html[data-theme="dark"] .stat-card,
  html[data-theme="dark"] .user-dropdown,
  html[data-theme="dark"] #notifPanel,
  html[data-theme="dark"] .doc-sidebar,
  html[data-theme="dark"] .doc-content,
  html[data-theme="dark"] .modal,
  html[data-theme="dark"] .modal-content,
  html[data-theme="dark"] .balence-display,
  html[data-theme="dark"] .chart-placeholder,
  html[data-theme="dark"] .pg-panel {
    background: #101624 !important;
    background-image: none !important;
    color: #e6ebf4 !important;
    border-color: #232d42 !important;
    box-shadow: 0 1px 3px rgba(0,0,0,.4) !important;
  }
  /* 文本颜色 */
  html[data-theme="dark"] h1, html[data-theme="dark"] h2, html[data-theme="dark"] h3,
  html[data-theme="dark"] h4, html[data-theme="dark"] .page-title, html[data-theme="dark"] .table-title,
  html[data-theme="dark"] .chart-title, html[data-theme="dark"] .stat-value,
  html[data-theme="dark"] .form-label, html[data-theme="dark"] td, html[data-theme="dark"] th,
  html[data-theme="dark"] label, html[data-theme="dark"] p, html[data-theme="dark"] span,
  html[data-theme="dark"] div, html[data-theme="dark"] li, html[data-theme="dark"] a,
  html[data-theme="dark"] .user-info-name, html[data-theme="dark"] .logo-text,
  html[data-theme="dark"] .dropdown-item, html[data-theme="dark"] .sidebar-item {
    color: #e6ebf4 !important;
  }
  html[data-theme="dark"] .page-subtitle, html[data-theme="dark"] .hint,
  html[data-theme="dark"] .stat-label, html[data-theme="dark"] .sidebar-section-title,
  html[data-theme="dark"] .user-info-uid, html[data-theme="dark"] .notif-time,
  html[data-theme="dark"] .muted, html[data-theme="dark"] .text-muted {
    color: #8a94a8 !important;
  }
  /* 表单控件 */
  html[data-theme="dark"] input, html[data-theme="dark"] select, html[data-theme="dark"] textarea,
  html[data-theme="dark"] .form-input, html[data-theme="dark"] .table-search {
    background: #0d1320 !important;
    color: #e6ebf4 !important;
    border-color: #2a3650 !important;
  }
  html[data-theme="dark"] input:focus, html[data-theme="dark"] select:focus,
  html[data-theme="dark"] textarea:focus, html[data-theme="dark"] .form-input:focus {
    border-color: #667eea !important;
    outline: none !important;
  }
  html[data-theme="dark"] input::placeholder, html[data-theme="dark"] textarea::placeholder { color: #5b667c !important; }
  /* 表格 */
  html[data-theme="dark"] th { background: #131a2b !important; color: #cdd5e4 !important; }
  html[data-theme="dark"] table, html[data-theme="dark"] td, html[data-theme="dark"] th { border-color: #232d42 !important; }
  html[data-theme="dark"] tr:hover td, html[data-theme="dark"] .friend-item:hover { background: #141c2e !important; }
  /* 侧边栏 */
  html[data-theme="dark"] .sidebar-item:hover,
  html[data-theme="dark"] .dropdown-item:hover,
  html[data-theme="dark"] .notif-item:hover,
  html[data-theme="dark"] .icon-btn:hover,
  html[data-theme="dark"] .icon-btn.danger:hover,
  html[data-theme="dark"] .icon-btn.success:hover,
  html[data-theme="dark"] .modal-close:hover,
  html[data-theme="dark"] .doc-nav-link:hover,
  html[data-theme="dark"] .nav-link:hover,
  html[data-theme="dark"] .notif-bell .bell-btn:hover { background: #182130 !important; }
  html[data-theme="dark"] .sidebar-item.active,
  html[data-theme="dark"] .nav-link.active,
  html[data-theme="dark"] .doc-nav-link.active {
    background: #1b2434 !important;
    color: #a5b4fc !important;
    border-left-color: #667eea !important;
  }
  /* 按钮 */
  html[data-theme="dark"] .btn-secondary { background: #232d42 !important; color: #e6ebf4 !important; border-color: #2a3650 !important; }
  html[data-theme="dark"] .btn-secondary:hover { background: #2c3a55 !important; }
  html[data-theme="dark"] .btn-danger { background: #3d1418 !important; color: #f5a3ad !important; border-color: #59212a !important; }
  html[data-theme="dark"] .btn-danger:hover { background: #521c22 !important; }
  /* 徽章 */
  html[data-theme="dark"] .badge-ok { background: #10321f !important; color: #6ee7a0 !important; }
  html[data-theme="dark"] .badge-off { background: #232d42 !important; color: #9aa5b8 !important; }
  html[data-theme="dark"] .badge-info { background: #14283e !important; color: #7db4f5 !important; }
  html[data-theme="dark"] .badge-danger, html[data-theme="dark"] .badge-err { background: #38141c !important; color: #f58ea0 !important; }
  html[data-theme="dark"] .sys-tag, html[data-theme="dark"] .post-tag { background: #1b2434 !important; color: #aab5c9 !important; }
  /* 提示条 */
  html[data-theme="dark"] .toast.success { background: #0e2a1c !important; color: #8ff0b8 !important; }
  html[data-theme="dark"] .toast.error { background: #33141a !important; color: #f5a3ad !important; }
  html[data-theme="dark"] .toast.info { background: #12263c !important; color: #93c2f8 !important; }
  html[data-theme="dark"] .toast-icon.success { color: #4ade80 !important; }
  html[data-theme="dark"] .toast-icon.error { color: #f87171 !important; }
  html[data-theme="dark"] .toast-icon.info { color: #60a5fa !important; }
  html[data-theme="dark"] .error-message { background: #33141a !important; color: #f5a3ad !important; }
  html[data-theme="dark"] .success-message { background: #0e2a1c !important; color: #8ff0b8 !important; }
  html[data-theme="dark"] .alert-error { background: #33141a !important; color: #f5a3ad !important; border-color: #59212a !important; }
  html[data-theme="dark"] .alert-success { background: #0e2a1c !important; color: #8ff0b8 !important; border-color: #1d5c3a !important; }
  /* 图形 tint 类（stat 图标块 / 趋势徽章 / 侧边栏徽章） */
  html[data-theme="dark"] .stat-icon.purple { background: rgba(102,126,234,.18) !important; color: #a5b4fc !important; }
  html[data-theme="dark"] .stat-icon.green { background: rgba(22,163,74,.18) !important; color: #4ade80 !important; }
  html[data-theme="dark"] .stat-icon.blue { background: rgba(37,99,235,.18) !important; color: #60a5fa !important; }
  html[data-theme="dark"] .stat-icon.orange { background: rgba(234,88,12,.18) !important; color: #fb923c !important; }
  html[data-theme="dark"] .stat-trend.up { background: rgba(22,163,74,.18) !important; color: #4ade80 !important; }
  html[data-theme="dark"] .stat-trend.down { background: rgba(220,38,38,.18) !important; color: #f87171 !important; }
  html[data-theme="dark"] .sidebar-badge { background: rgba(217,119,6,.22) !important; color: #fbbf24 !important; }
  /* 杂项 */
  html[data-theme="dark"] .dropdown-divider { background: #232d42 !important; }
  html[data-theme="dark"] .card-icon { background: #1b2434 !important; }
  html[data-theme="dark"] .modal-close { background: transparent !important; color: #8a94a8 !important; }
  html[data-theme="dark"] code, html[data-theme="dark"] pre {
    background: #0d1320 !important; color: #d7deeb !important; border-color: #232d42 !important;
  }
  html[data-theme="dark"] ::-webkit-scrollbar-track { background: #0b0f19 !important; }
  html[data-theme="dark"] ::-webkit-scrollbar-thumb { background: #2a3650 !important; }
  /* 主题切换按钮 */
  html[data-theme="dark"] .theme-toggle { color: #8a94a8 !important; }
  html[data-theme="dark"] .theme-toggle:hover { background: #182130 !important; color: #e6ebf4 !important; }
  /* 图表周期切换 tabs（7天/30天/90天） */
  html[data-theme="dark"] .chart-tabs { background: #0d1320 !important; }
  html[data-theme="dark"] .chart-tab { color: #8a94a8 !important; }
  html[data-theme="dark"] .chart-tab:hover { color: #e6ebf4 !important; }
  html[data-theme="dark"] .chart-tab.active { background: #232d42 !important; color: #e6ebf4 !important; box-shadow: none !important; }
  /* 快速操作卡片 */
  html[data-theme="dark"] .apikey-card { background: #101624 !important; border-color: #232d42 !important; }
  html[data-theme="dark"] .apikey-item { background: #0d1320 !important; border-color: #232d42 !important; }
  html[data-theme="dark"] .apikey-item:hover { background: #141c2e !important; }
  html[data-theme="dark"] .apikey-icon { background: #1a2236 !important; }

  /* ===== 全站暗色补丁：上一轮漏网、带图形/容器的浅色元素 ===== */
  html[data-theme="dark"] .billing-banner { background: #16203a !important; border-color: #2a3650 !important; color: #cdd5e4 !important; }
  html[data-theme="dark"] .billing-banner .bb-time { color: #a5b4fc !important; }
  /* 仪表盘「可用模型」列表（调用模型页签）：浅灰卡 + 白复制按钮在暗色下改深色 */
  html[data-theme="dark"] .model-item { background: #151d2e !important; border-color: #232d42 !important; color: #e6ebf4 !important; }
  html[data-theme="dark"] .model-item .copy-btn { background: #1b2434 !important; color: #9db4f0 !important; border-color: #2a3650 !important; }
  html[data-theme="dark"] .model-item .copy-btn:hover { background: #2c3a55 !important; }
  /* 调用模型 / playground 布局容器 */
  html[data-theme="dark"] .pg-convs,
  html[data-theme="dark"] .pg-main,
  html[data-theme="dark"] .pg-toolbar,
  html[data-theme="dark"] .pg-inputbar,
  html[data-theme="dark"] .pg-syspanel { background: #101624 !important; border-color: #232d42 !important; color: #e6ebf4 !important; }
  html[data-theme="dark"] .pg-convs-head { border-color: #232d42 !important; }
  html[data-theme="dark"] .pg-convs-head span { color: #8a94a8 !important; }
  html[data-theme="dark"] .pg-convs-hint { color: #8a94a8 !important; border-color: #232d42 !important; }
  html[data-theme="dark"] .pg-msg.assistant .bubble { background: #0d1320 !important; color: #e6ebf4 !important; border-color: #232d42 !important; }
  /* 会话列表项：hover/active/标题/删除按钮 */
  html[data-theme="dark"] .pg-conv:hover { background: #1b2434 !important; }
  html[data-theme="dark"] .pg-conv.active { background: #232d42 !important; }
  html[data-theme="dark"] .pg-conv-title { color: #cdd5e4 !important; }
  html[data-theme="dark"] .pg-conv.active .pg-conv-title { color: #9db4f0 !important; }
  html[data-theme="dark"] .pg-conv-del { color: #6b7690 !important; }
  html[data-theme="dark"] .pg-conv-del:hover { color: #ff9aa8 !important; background: #3a1d24 !important; }
  /* 用户消息气泡（浅紫底深字 → 暗底浅字） */
  html[data-theme="dark"] .pg-msg.user .bubble { background: #232d42 !important; color: #dbe3f2 !important; }
  html[data-theme="dark"] .pg-msg.error .bubble { background: #2a1418 !important; color: #ff9aa8 !important; border-color: #4a222c !important; }
  html[data-theme="dark"] .pg-tool-btn { background: #1b2434 !important; color: #cdd5e4 !important; border-color: #2a3650 !important; }
  /* 文档页 intro 提示块 */
  html[data-theme="dark"] .doc-intro { background: #131a2b !important; border-color: #2a3650 !important; color: #aab5c9 !important; }
  /* 帖子卡片（社区/帖子广场/收藏/详情/管理） */
  html[data-theme="dark"] .post-card { background: #101624 !important; border-color: #232d42 !important; color: #e6ebf4 !important; box-shadow: 0 1px 3px rgba(0,0,0,.4) !important; }
  /* 空状态 */
  html[data-theme="dark"] .empty-state { background: #101624 !important; border-color: #232d42 !important; color: #8a94a8 !important; }
  html[data-theme="dark"] .empty-state i { color: #4b566b !important; }
  html[data-theme="dark"] .empty-state .sub { color: #6b7488 !important; }
  /* 社交聊天容器 */
  html[data-theme="dark"] .chat-container,
  html[data-theme="dark"] .message-container { background: #0d1320 !important; border-color: #232d42 !important; color: #e6ebf4 !important; }
  /* 标签页（白底） */
  html[data-theme="dark"] .tabs { background: #101624 !important; border-color: #232d42 !important; }
  html[data-theme="dark"] .tab.active { background: #1b2434 !important; color: #e6ebf4 !important; }
  /* 统计小卡（IP 审计 / 审计页） */
  html[data-theme="dark"] .stat { background: #101624 !important; border-color: #232d42 !important; color: #cdd5e4 !important; box-shadow: 0 1px 3px rgba(0,0,0,.4) !important; }
  html[data-theme="dark"] .stat-chip { background: #131a2b !important; border-color: #232d42 !important; color: #aab5c9 !important; }
  html[data-theme="dark"] .stat-chip b { color: #e6ebf4 !important; }
  /* 任务表 / 表头（管理任务页） */
  html[data-theme="dark"] .tasks-table,
  html[data-theme="dark"] .table-header { background: #101624 !important; border-color: #232d42 !important; color: #e6ebf4 !important; }
  /* 站内 toast（社交/聊天/任务等白底 toast） */
  html[data-theme="dark"] .toast { background: #1b2434 !important; color: #e6ebf4 !important; box-shadow: 0 4px 12px rgba(0,0,0,.5) !important; }
  html[data-theme="dark"] .toast-icon { color: #a5b4fc !important; }

  /* ===== 暗色补丁（续）：大块浅色容器 / 按钮 / 徽章（第二轮全站扫描发现的漏网） ===== */
  /* 大块浅色容器 */
  html[data-theme="dark"] .friend-item { background: #101624 !important; border-color: #232d42 !important; color: #e6ebf4 !important; }
  html[data-theme="dark"] .conversation-list { background: #0d1320 !important; border-color: #232d42 !important; color: #e6ebf4 !important; }
  html[data-theme="dark"] .chat-window { background: #0d1320 !important; border-color: #232d42 !important; color: #e6ebf4 !important; }
  html[data-theme="dark"] .notif-card { background: #101624 !important; border-color: #232d42 !important; color: #e6ebf4 !important; box-shadow: 0 1px 3px rgba(0,0,0,.4) !important; }
  html[data-theme="dark"] .login-container { background: #101624 !important; border-color: #232d42 !important; color: #e6ebf4 !important; }
  html[data-theme="dark"] .security-notice { background: #131a2b !important; border-color: #2a3650 !important; color: #aab5c9 !important; }
  /* 按钮类浅色表面（白底 -> 暗底） */
  html[data-theme="dark"] .recharge-btn { background: #1b2434 !important; color: #cdd5e4 !important; border-color: #2a3650 !important; }
  html[data-theme="dark"] .chart-refresh { background: #1b2434 !important; color: #cdd5e4 !important; border-color: #2a3650 !important; }
  html[data-theme="dark"] .page-btn { background: #1b2434 !important; color: #cdd5e4 !important; border-color: #2a3650 !important; }
  html[data-theme="dark"] .page-btn:hover { background: #2c3a55 !important; }
  html[data-theme="dark"] .day-chk { background: #1b2434 !important; color: #cdd5e4 !important; border-color: #2a3650 !important; }
  html[data-theme="dark"] .btn.secondary,
  html[data-theme="dark"] .btn-secondary { background: #232d42 !important; color: #e6ebf4 !important; border-color: #2a3650 !important; }
  /* 浮动主题切换按钮自身（白底 -> 暗底） */
  html[data-theme="dark"] .theme-toggle-float { background: #1b2434 !important; color: #8a94a8 !important; box-shadow: 0 4px 16px rgba(0,0,0,.5) !important; }
  /* 徽章：浅底 + 浅字（看不清） -> 暗底 + 对应色字 */
  html[data-theme="dark"] .badge-low { background: #10321f !important; color: #6ee7a0 !important; }
  html[data-theme="dark"] .badge-medium { background: #2a2310 !important; color: #fbbf24 !important; }
  html[data-theme="dark"] .badge-warn { background: #2a2310 !important; color: #fbbf24 !important; }
  /* 设置页切换开关：OFF 态轨道（浅灰 #d1d5db）在暗色下改深色，旋钮保持浅色 */
  html[data-theme="dark"] .switch input:not(:checked) + .slider { background: #2a3650 !important; }
  html[data-theme="dark"] .switch input:not(:checked) + .slider:before { background: #cdd5e4 !important; }
  /* 登录/注册页（auth-card 白卡在暗色下改深色，内部文字浅色化） */
  html[data-theme="dark"] .auth-card { background: #151d2e !important; box-shadow: 0 4px 24px rgba(0,0,0,.45) !important; }
  html[data-theme="dark"] .auth-title { color: #e6ebf4 !important; }
  html[data-theme="dark"] .auth-subtitle { color: #9aa7bd !important; }
  html[data-theme="dark"] .form-label { color: #c7d0e0 !important; }
  html[data-theme="dark"] .auth-card .form-input { background: #1e2940 !important; border-color: #2a3650 !important; color: #e6ebf4 !important; }
  html[data-theme="dark"] .auth-card .form-input::placeholder { color: #5d6b85 !important; }
  html[data-theme="dark"] .forgot-password { color: #9db4f0 !important; }
  html[data-theme="dark"] .auth-switch { color: #9aa7bd !important; }
  html[data-theme="dark"] .auth-switch a { color: #8fa3f5 !important; }
  html[data-theme="dark"] .auth-footer { color: #6b7a94 !important; }
  html[data-theme="dark"] .btn-code { background: #232d42 !important; color: #9db4f0 !important; border-color: #2a3650 !important; }
  html[data-theme="dark"] .captcha-track { background: #1e2940 !important; }
  html[data-theme="dark"] .captcha-text { color: #c7d0e0 !important; }
  html[data-theme="dark"] .captcha-msg { color: #9aa7bd !important; }
  html[data-theme="dark"] .error-message { background: #3a1d24 !important; color: #ff9aa8 !important; }
  html[data-theme="dark"] .success-message { background: #10321f !important; color: #6ee7a0 !important; }
  /* 模型价格页：浅灰价格行 + 峰/谷浅底标签 */
  html[data-theme="dark"] .price-row { background: #151d2e !important; border-color: #232d42 !important; }
  html[data-theme="dark"] .price-row code { color: #cdd5e4 !important; }
  html[data-theme="dark"] .tier-tag.peak { background: #3a1d24 !important; color: #ff9aa8 !important; }
  html[data-theme="dark"] .tier-tag.offpeak { background: #10321f !important; color: #6ee7a0 !important; }
  html[data-theme="dark"] .tier-tag.standard { background: #232d42 !important; color: #9aa7bd !important; }
  /* 仪表盘计费横幅的 tier 药丸（class 为 .tier-pill，与模型价格页的 .tier-tag 平行，需单独覆盖） */
  html[data-theme="dark"] .tier-pill.peak { background: #3a1d24 !important; color: #ff9aa8 !important; }
  html[data-theme="dark"] .tier-pill.offpeak { background: #10321f !important; color: #6ee7a0 !important; }
  html[data-theme="dark"] .tier-pill.std { background: #232d42 !important; color: #9aa7bd !important; }

"""

# bootstrap：head 内同步执行 —— 亮暗唯一控制器。
# 挂载方式优先 constructable stylesheet（document.adoptedStyleSheets，纯 CSSOM、
# 不受 CSP 限制、浅色时零暗色 CSS 进文档）；不支持的老浏览器回退 <style> disabled 开关。
_THEME_BOOTSTRAP_JS = """<script>
(function () {
  var DARK_CSS = '__THEME_DARK_CSS_JSON__';
  var sheet = null;
  function adopt(on) {
    var root = document.documentElement;
    try {
      if (on && !sheet) {
        if (window.CSSStyleSheet && CSSStyleSheet.prototype.replaceSync &&
            Array.isArray(document.adoptedStyleSheets)) {
          sheet = new CSSStyleSheet();
          sheet.replaceSync(DARK_CSS);
          sheet.__adopt = true;
        } else {
          sheet = document.createElement('style');
          sheet.textContent = DARK_CSS;
          (document.head || document.documentElement).appendChild(sheet);
          sheet.__adopt = false;
        }
      }
      if (sheet) {
        if (sheet.__adopt) document.adoptedStyleSheets = on ? [sheet] : [];
        else sheet.disabled = !on;
      }
    } catch (e) { /* 属性仍会翻转，模板内暗色规则可部分生效 */ }
    root.setAttribute('data-theme', on ? 'dark' : 'light');
  }
  try {
    var m = localStorage.getItem('apiproxy_theme') || 'auto';
    if (m === 'auto') m = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    adopt(m === 'dark');
  } catch (e) { adopt(false); }
  window.__apxThemeAdopt = adopt;
})();
</script>""".replace("'__THEME_DARK_CSS_JSON__'", json.dumps(_THEME_DARK_CSS))

_THEME_CHARTS_JS = """<script>
(function () {
  // Chart.js 暗色 re-theme（Chart.js 无原生暗色主题）。
  // 关键实现细节：Chart.js 4 的 chart.options 是带缓存的解析代理，直接写入会丢失；
  // 必须修改原始配置 chart.config.options（构造前变换 cfg），再触发 update 重绘。
  function isDark() { return document.documentElement.getAttribute('data-theme') === 'dark'; }
  function themeConfig(o, dk) {
    if (!o) return;
    o.plugins = o.plugins || {};
    var lg = o.plugins.legend = o.plugins.legend || {};
    if (lg.display !== false) {
      lg.labels = lg.labels || {};
      lg.labels.color = dk ? '#c3ccdd' : '#374151';
    }
    var tp = o.plugins.tooltip = o.plugins.tooltip || {};
    tp.backgroundColor = dk ? 'rgba(13,19,32,.96)' : 'rgba(0,0,0,.8)';
    tp.titleColor = '#f2f5fa';
    tp.bodyColor = '#dde4f0';
    tp.borderColor = dk ? '#2c3a55' : 'transparent';
    tp.borderWidth = dk ? 1 : 0;
    var sc = o.scales;
    if (sc) {
      Object.keys(sc).forEach(function (k) {
        var s = sc[k] = sc[k] || {};
        s.ticks = s.ticks || {};
        s.ticks.color = dk ? '#8a94a8' : '#6b7280';
        if (!s.grid) s.grid = {};
        if (s.grid.display !== false) s.grid.color = dk ? 'rgba(140,155,185,.14)' : 'rgba(0,0,0,.07)';
        s.border = s.border || {};
        s.border.color = dk ? '#232d42' : '#e5e7eb';
      });
    }
  }
  function themeChart(c) {
    try {
      if (!c) return;
      var dk = isDark();
      if (c.$apxDark === dk) return;
      c.$apxDark = dk;
      var raw = (c.config && c.config.options) ? c.config.options : null;
      if (!raw) return;
      themeConfig(raw, dk);
      c.update('none');
    } catch (e) {}
  }
  function themeAll() {
    if (!window.Chart || !Chart.instances) return;
    try {
      Object.keys(Chart.instances).forEach(function (id) { themeChart(Chart.instances[id]); });
    } catch (e) {}
  }
  function patch() {
    if (!window.Chart || window.Chart.__apxThemed) return;
    var Orig = window.Chart;
    var Wrapped = function (ctx, cfg) {
      var inst;
      if (cfg) {
        try { cfg.options = cfg.options || {}; themeConfig(cfg.options, isDark()); } catch (e) {}
        inst = new Orig(ctx, cfg);
        inst.$apxDark = isDark();
      } else {
        inst = new Orig(ctx);
      }
      return inst;
    };
    Wrapped.prototype = Orig.prototype;
    Object.keys(Orig).forEach(function (k) { try { Wrapped[k] = Orig[k]; } catch (e) {} });
    Wrapped.__apxThemed = true;
    window.Chart = Wrapped;
  }
  patch();
  [200, 600, 1200, 2500, 5000, 8000].forEach(function (t) {
    setTimeout(function () { patch(); themeAll(); }, t);
  });
  window.addEventListener('load', themeAll);
  window.addEventListener('themechange', themeAll);
  if (window.MutationObserver) {
    var mo = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        if (muts[i].addedNodes && muts[i].addedNodes.length) { setTimeout(themeAll, 100); break; }
      }
    });
    try { mo.observe(document.body, { childList: true, subtree: true }); } catch (e) {}
  }
})();
</script>"""

_THEME_UI_JS = """<style>
/* 主题切换按钮基础样式（与主题无关，始终生效） */
.theme-toggle { display: inline-flex; align-items: center; gap: 6px; background: transparent; border: none; cursor: pointer; color: #6b7280; font-size: 15px; padding: 8px 10px; border-radius: 10px; transition: background .15s, color .15s; font-family: inherit; }
.theme-toggle:hover { background: #f3f4f6; color: #111827; }
.theme-toggle .tt-label { font-size: 13px; font-weight: 500; }
.theme-toggle-float { position: fixed; right: 16px; bottom: 16px; z-index: 9000; background: #ffffff; box-shadow: 0 4px 16px rgba(15, 23, 42, .12); }
/* 主题切换过渡：仅在切换瞬间由 JS 挂到 <html> 上，完成后摘除。
   不常驻，避免全站常驻 transition 拖慢 hover 等交互动画。 */
html.theme-transitioning, html.theme-transitioning *,
html.theme-transitioning *::before, html.theme-transitioning *::after {
  transition: background-color .38s ease, color .38s ease, border-color .38s ease,
              box-shadow .38s ease, fill .38s ease, stroke .38s ease !important;
}
</style>
<script>
(function () {
  var KEY = 'apiproxy_theme';
  var MODES = ['light', 'dark', 'auto'];
  var META = {
    light: { icon: 'bi-sun', label: '浅色' },
    dark:  { icon: 'bi-moon-stars', label: '深色' },
    auto:  { icon: 'bi-circle-half', label: '自动' }
  };
  function current() {
    try { return localStorage.getItem(KEY) || 'auto'; } catch (e) { return 'auto'; }
  }
  function resolved(m) {
    if (m !== 'auto') return m;
    try { return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; }
    catch (e) { return 'light'; }
  }
  var _tt = null;
  function apply(m) {
    var root = document.documentElement;
    var reduce = false;
    try { reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) {}
    if (!reduce) {
      // JS 自动调节：切换瞬间挂过渡类，全站颜色平滑渐变；完成后摘除
      root.classList.add('theme-transitioning');
      if (_tt) clearTimeout(_tt);
      _tt = setTimeout(function () { root.classList.remove('theme-transitioning'); }, 480);
    }
    // 亮暗只由 JS 调节：同一控制器负责样式表挂载 + data-theme 属性
    if (window.__apxThemeAdopt) window.__apxThemeAdopt(resolved(m) === 'dark');
    else root.setAttribute('data-theme', resolved(m));
    try { window.dispatchEvent(new CustomEvent('themechange')); } catch (e) {}
  }
  function render() {
    var b = document.getElementById('themeToggle');
    if (!b) return;
    var m = current();
    var t = META[m];
    b.innerHTML = '<i class="bi ' + t.icon + '"></i><span class="tt-label">' + t.label + '</span>';
    b.title = '主题：' + t.label + '（点击切换）';
  }
  function cycle() {
    var m = MODES[(MODES.indexOf(current()) + 1) % MODES.length];
    try { localStorage.setItem(KEY, m); } catch (e) { /* ignore */ }
    apply(m);
    render();
  }
  function mount() {
    if (document.getElementById('themeToggle')) return;
    var b = document.createElement('button');
    b.id = 'themeToggle';
    b.type = 'button';
    b.className = 'theme-toggle';
    b.addEventListener('click', cycle);
    var nr = document.querySelector('.navbar-right');
    if (nr) { nr.insertBefore(b, nr.firstChild); }
    else { b.classList.add('theme-toggle-float'); document.body.appendChild(b); }
    render();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
  try {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () { apply(current()); });
  } catch (e) { /* ignore */ }
})();
</script>"""

_PROGRESS_HTML = """<style>
.wb-loading { position: relative; }
.wb-loading::after { content: ''; position: absolute; inset: 0; border-radius: inherit; pointer-events: none;
  background: linear-gradient(100deg, rgba(255,255,255,0) 25%, rgba(102,126,234,.18) 50%, rgba(255,255,255,0) 75%);
  background-size: 200% 100%; animation: wbShimmerMove 1.2s linear infinite; }
.wb-loading > * { opacity: .35; transition: opacity .2s ease; }
@keyframes wbShimmerMove { from { background-position: 200% 0; } to { background-position: -200% 0; } }
html[data-theme="dark"] .wb-loading::after {
  background: linear-gradient(100deg, rgba(255,255,255,0) 25%, rgba(255,255,255,.07) 50%, rgba(255,255,255,0) 75%);
  background-size: 200% 100%; }
</style>
<div id="wbTopProgress" style="position:fixed;top:0;left:0;height:3px;width:0;opacity:1;background:linear-gradient(90deg,#667eea,#764ba2);z-index:99999;transition:width .25s ease,opacity .3s ease;pointer-events:none;"></div>
<script>
(function () {
  var p = document.getElementById('wbTopProgress');
  if (!p) return;
  // ================= 进度条：真实步骤制 =================
  // 一步 = 一次数据 GET 请求从发出 -> body 被页面消费(json/text) -> 浏览器画完一帧。
  // 100% 只在所有步骤完成且静默 400ms 后出现；绝不假报。
  var w = 0, done = false, loadFired = false, pending = 0, total = 0, completed = 0;
  var creepTimer = null, finishTimer = null, capTimer = null;
  function render() { p.style.width = w + '%'; }
  function recompute() {
    if (total > 0) {
      // 真实进度：底座 12% + 已完成步骤占比 * 78%（100% 留给真正收尾）
      var target = 12 + 78 * (completed / total);
      if (target > w) { w = target; render(); }
    } else if (!done) {
      // 还不知道有几个步骤：缓慢爬到 12% 封顶，不许再高
      w = Math.min(w + 0.4, 12); render();
    }
  }
  creepTimer = setInterval(recompute, 150);
  function reallyFinish() {
    if (done) return; done = true;
    clearInterval(creepTimer);
    if (capTimer) clearTimeout(capTimer);
    if (finishTimer) { clearTimeout(finishTimer); finishTimer = null; }
    p.style.width = '100%';
    setTimeout(function () { p.style.opacity = '0'; }, 250);
  }
  function maybeFinish() {
    if (done || !loadFired) return;
    if (pending > 0 || busy > 0) {
      // 有步骤在跑或页面声明了渲染占用，撤销已排定的收尾
      if (finishTimer) { clearTimeout(finishTimer); finishTimer = null; }
      return;
    }
    // 静默 650ms 才收尾：页面经常分批串行拉数据，批间 pending 会瞬时归零，
    // 立即收尾就是"没加载完进度条就到头"的根因
    if (!finishTimer) finishTimer = setTimeout(function () { finishTimer = null; reallyFinish(); }, 650);
  }
  // 渲染占用通道：页面开始重渲染（如图表入场动画）时 wbStepBusy(true)，
  // 渲染完成回调里 wbStepBusy(false)。期间进度条不许收尾。
  // 自带 6s 看门狗：图表中途被 destroy 导致完成回调丢失时自动释放，防卡死。
  var busy = 0;
  window.wbStepBusy = function (on) {
    if (on) {
      busy++;
      if (finishTimer) { clearTimeout(finishTimer); finishTimer = null; }
      setTimeout(function () {
        if (busy > 0) { busy--; if (loadFired) maybeFinish(); }
      }, 6000);
    } else {
      if (busy > 0) busy--;
      if (loadFired) maybeFinish();
    }
  };
  function armCap() {
    if (capTimer || done) return;
    capTimer = setTimeout(function () {
      if (done) return; done = true; clearInterval(creepTimer);
      if (finishTimer) { clearTimeout(finishTimer); finishTimer = null; }
      p.style.opacity = '0';  // 兜底退出：淡出但不谎报 100%
    }, 15000);
  }
  window.addEventListener('load', function () { loadFired = true; armCap(); maybeFinish(); });
  if (document.readyState === 'complete') { loadFired = true; armCap(); maybeFinish(); }
  if (window.fetch) {
    var _f = window.fetch;
    window.fetch = function () {
      var a = arguments;
      var url = (a[0] && (a[0].url || a[0])) || '';
      var opt = a[1] || {};
      var method = (opt.method || 'GET').toUpperCase();
      var isPoll = /(?:\\/api\\/(?:chat\\/unread|stream|notifications|userinfo|models)|EventSource|\\/sse\\/)/i.test(String(url));
      if (done || method !== 'GET' || isPoll) return _f.apply(this, a);
      pending++; total++;
      if (finishTimer) { clearTimeout(finishTimer); finishTimer = null; }
      if (w < 25) { w = 25; render(); }
      var stepDone = function () {
        // 渲染近似：等浏览器真正画完一帧（两层 rAF）再记这一步完成
        requestAnimationFrame(function () { requestAnimationFrame(function () {
          pending--; completed++; recompute(); maybeFinish();
        }); });
      };
      var stepGuard = setTimeout(stepDone, 12000);  // 单步保险：页面没消费 body 也不无限卡住
      var tracked = _f.apply(this, a).then(function (r) {
        // 请求"完成"必须是 body 被页面消费之后：包装 json/text，消费完才记步
        try {
          var rj = r.json.bind(r), rt = r.text.bind(r);
          var wrap = function (fn) { return function () {
            return fn.apply(null, arguments).then(function (v) { clearTimeout(stepGuard); stepDone(); return v; },
                                                  function (e) { clearTimeout(stepGuard); stepDone(); throw e; });
          }; };
          r.json = wrap(rj); r.text = wrap(rt);
        } catch (e) { clearTimeout(stepGuard); stepDone(); }
        return r;
      }, function (e) { clearTimeout(stepGuard); stepDone(); throw e; });
      return tracked;
    };
  }
  // ================= 全屏/窗口切换回流修复 =================
  // Chromium 在 Windows 缩放环境下退出全屏后偶发沿用旧缩放比例的光栅结果，
  // 表现为内容保持全屏时的大小、必须手动刷新。强制重排一次并广播 resize，
  // 让 Chart.js 等依赖 resize 的组件自行重适配。
  function kickRepaint(dispatchResize) {
    var b = document.body; if (!b) return;
    try {
      b.style.transform = 'translateZ(0)';
      void b.offsetHeight;
      setTimeout(function () { b.style.transform = ''; }, 60);
      if (dispatchResize) window.dispatchEvent(new Event('resize'));
    } catch (e) { /* ignore */ }
  }
  try {
    document.addEventListener('fullscreenchange', function () { setTimeout(function () { kickRepaint(true); }, 120); });
  } catch (e) { /* ignore */ }
  var _rzT = null;
  window.addEventListener('resize', function () {
    if (_rzT) clearTimeout(_rzT);
    _rzT = setTimeout(function () { kickRepaint(false); }, 200);
  });
  // ================= Shimmer 助手（全局可用） =================
  // wbShimmer.start(el) / wbShimmer.done(el)：给容器加流动微光遮罩，表示内容仍在加载。
  // 自动向上找 .chart-card 容器；其它容器直接传元素本身即可。
  window.wbShimmer = {
    start: function (el) {
      var c = el && el.closest ? (el.closest('.chart-card') || el) : null;
      if (c) c.classList.add('wb-loading');
    },
    done: function (el) {
      // 摘除可能挂在 .chart-card、canvas 直接父容器（HTML 预置的首帧微光）或元素本身上的微光
      var c = el && el.closest ? el.closest('.chart-card') : null;
      if (c) c.classList.remove('wb-loading');
      if (el && el.parentElement && el.parentElement.classList) el.parentElement.classList.remove('wb-loading');
      if (el && el.classList) el.classList.remove('wb-loading');
    }
  };
  // 看门狗：load 后 15s 仍残留的微光（loader 未跑到/提前退出）一律清除，防僵尸遮罩
  window.addEventListener('load', function () {
    setTimeout(function () {
      try {
        document.querySelectorAll('.wb-loading').forEach(function (n) { n.classList.remove('wb-loading'); });
      } catch (e) { /* ignore */ }
    }, 15000);
  });
})();
</script>"""


def _is_cors_endpoint(path: str) -> bool:
    """判断路径是否允许跨域访问。"""
    return path.startswith('/oauth/') or path == '/api/oauth' or path.startswith('/api/oauth/')


_ADMIN_ROUTE_PREFIXES = ('/admin', '/api/admin')


def _is_admin_route(path: str) -> bool:
    """判断路径是否属管理/特权路由（供堡垒机记录）。"""
    return any(path.startswith(p) for p in _ADMIN_ROUTE_PREFIXES)


async def _waf_record_event(client_ip: str, rule: str, reason: str) -> None:
    """将 WAF 拦截记录到 security_events"""
    try:
        await async_db_query(
            "INSERT INTO security_events (event_type, severity, risk_score, client_ip, details, action_taken) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ('waf_block', 'warn', 30, client_ip, f"rule={rule}; {reason}", 'blocked')
        )
    except Exception as e:
        logging.error(f"WAF record event failed: {e}")


async def _ids_record_event(client_ip: str, ev: dict) -> None:
    """将 IDS/IPS 告警记录到 security_events（event_type='ids_alert'）。

    ev: {rule, severity, score, reason, detail, action_taken?}
    """
    try:
        action = ev.get('action_taken') or ('blocked' if ev.get('action') == 'block' else 'detected')
        await async_db_query(
            "INSERT INTO security_events (event_type, severity, risk_score, client_ip, details, action_taken) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ('ids_alert', ev.get('severity', 'medium'), int(ev.get('score', 0)),
             client_ip, f"rule={ev.get('rule')}; {ev.get('reason')} | {ev.get('detail', '')}", action)
        )
    except Exception as e:
        logging.error(f"IDS/IPS record event failed: {e}")


async def _ids_ban_ip(client_ip: str, reason: str) -> None:
    """通过 IDS/IPS 触发 IP 自动封禁（写入 ip_blacklist，与 WAF 共用机制）。"""
    try:
        from ..security import ban_ip_auto
        await ban_ip_auto(async_db_query, client_ip, 'minutes',
                          _ids._ban_minutes(), reason)
        logging.warning(f"IDS/IPS auto-ban IP {client_ip}: {reason}")
    except Exception as e:
        logging.error(f"IDS/IPS auto-ban failed: {e}")


def register_middleware(app):
    """在 Quart app 上注册所有中间件。"""
    # IP 审计模式路由（/ip-audit 等待页、SSE 状态、grant 换取）
    from .. import ip_audit as _ipa_mod
    _ipa_mod.register_routes(app)

    @app.before_request
    async def _kill_switch_gate():
        """全局熔断开关（kill switch）：应急止血，必须最先执行。

        激活后所有非豁免请求立即 503；回环/内网默认豁免（KILL_SWITCH_ALLOW_PRIVATE），
        /api/console/exec 永远放行（带 Debug Console 密钥鉴权），保证公网管理员仍能 kill_off。
        """
        try:
            from .. import kill_switch as _ks
            path = request.path or ''
            if path == '/api/console/exec' or path.startswith('/api/console/'):
                return
            verdict = _ks.check(_get_client_ip())
            if verdict.get('blocked'):
                return jsonify({
                    'error': 'Service temporarily unavailable (emergency kill switch active)',
                    'reason': verdict.get('reason') or 'manual',
                }), 503
        except Exception as e:
            logging.error(f"kill switch check failed: {e}")

    @app.before_request
    async def _generate_csp_nonce():
        """为每个请求生成唯一 CSP nonce（供内联 <script>/<style> 使用）。

        每次请求随机生成，攻击者无法预知，从而在移除 'unsafe-inline'
        后仍允许受信的内联脚本/样式执行。
        """
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.before_request
    async def _ip_access_gate():
        """IP 直接访问策略：按 Host 头判定裸 IP 访问，按 IP_ACCESS_MODE 处置。

        背景：TLS 证书签给域名，浏览器用裸 IP 访问必然证书不匹配，session cookie
        还可能经明文 HTTP 传输。allow=旧行为；secure=cookie 强制带 Secure 属性
        （在 app.py 全局生效，此处无需动作）；deny=直接 403（回环豁免可配）；
        audit=下发 IP 强绑定的 Access ID 等管理员审批（详见 ip_audit.py）。
        注册在 _generate_csp_nonce 之后：audit 等待页的内联脚本需要本次请求的 nonce。
        运行时读 configs 模块属性，便于控制台热改配置后即时生效。
        """
        mode = str(getattr(_seq_configs, 'IP_ACCESS_MODE', 'allow') or 'allow').strip().lower()
        if mode == 'allow':
            return
        host = request.host or ''
        if not host:
            return  # HTTP/1.0 无 Host 头（健康探针等），不误伤
        try:
            hostname = urlparse(f'//{host}').hostname or ''
        except ValueError:
            hostname = ''
        if not hostname:
            return
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            return  # 域名访问，不受限
        if mode == 'secure':
            return
        if getattr(_seq_configs, 'IP_ACCESS_LOCAL_EXEMPT', True) and ip.is_loopback:
            return
        if mode == 'audit':
            from .. import ip_audit as _ipa
            if request.path.startswith('/ip-audit'):
                return  # 等待页 / SSE / grant 换取自身的流转路径
            # 有效访问 Token（绑定 IP、未吊销、未过期）→ 放行
            if _ipa.check_token(request.cookies.get(_ipa.COOKIE_NAME),
                                _get_client_ip()).get('ok'):
                return
            rec = _ipa.get_or_create(_get_client_ip())
            if rec is None:
                return jsonify({'error': 'Audit queue is full, try again later.',
                                'code': 'ip_audit_busy'}), 503
            if request.path.startswith(('/api/', '/v1/')) or \
                    'application/json' in (request.headers.get('Accept') or ''):
                return jsonify({'error': 'Direct IP access pending administrator audit.',
                                'code': 'ip_audit_pending',
                                'access_id': rec['access_id']}), 403
            # HTML 请求：下发等待页（403 + 审计页内容）
            return _ipa.Response(_ipa.render_page(rec, getattr(g, 'csp_nonce', '')),
                                 mimetype='text/html'), 403
        # mode == 'deny'
        logging.warning(f"IP 直接访问被拒绝：host={host} path={request.path} "
                        f"client_ip={_get_client_ip()}")
        return jsonify({'error': 'Direct IP access is not allowed. '
                                 'Please access via the configured domain.',
                        'code': 'ip_access_denied'}), 403

    @app.before_request
    async def _waf_before_request():
        """全站 WAF 规则检查 + 行为监测"""
        if request.method == 'OPTIONS':
            return
        path = request.path or ''
        if path.startswith('/static/'):
            return

        client_ip = _get_client_ip()

        try:
            wl = await _whitelist_bypass(client_ip)
        except Exception:
            wl = set()

        # 1) 全站 IP 黑名单强制
        if 'all' not in wl and 'blacklist' not in wl:
            try:
                rows = await async_db_query(
                    "SELECT reason, ban_expire_at FROM ip_blacklist "
                    "WHERE ip = ? AND (ban_expire_at IS NULL OR ban_expire_at > ?)",
                    (client_ip, time.time())
                )
                if rows:
                    return jsonify({'error': 'Access denied: your IP has been blocked'}), 403
            except Exception as e:
                logging.error(f"WAF ip_blacklist check failed: {e}")

        # 2) WAF 规则检查
        if _waf.WAF_ENABLED and 'all' not in wl:
            behind_cf = _waf.WAF_DISABLE_IF_CLOUDFLARE and _waf.is_behind_cloudflare(request)
            if not behind_cf:
                try:
                    blocked, reason, status, rule = await _waf.waf_inspect_request(request, client_ip)
                    if blocked:
                        await _waf_record_event(client_ip, rule, reason)
                        should_ban, bmsg, _, cnt = _waf.behavior_record_violation(client_ip)
                        if should_ban and 'autoban' not in wl:
                            try:
                                from ..security import ban_ip_auto
                                await ban_ip_auto(async_db_query, client_ip, 'minutes',
                                                  _waf.WAF_BAN_MINUTES, bmsg)
                                logging.warning(f"WAF auto-ban IP {client_ip}: {bmsg}")
                                await _waf_record_event(client_ip, 'behavior_ban', bmsg)
                            except Exception as e:
                                logging.error(f"WAF auto-ban failed: {e}")
                        return jsonify({'error': f'Request blocked by WAF: {reason}'}), status
                except Exception as e:
                    logging.error(f"WAF inspect failed: {e}")

        # 3) 全局每 IP 行为频率
        if 'all' not in wl and 'ratelimit' not in wl:
            try:
                blocked, reason, status = _waf.behavior_record_request(client_ip)
                if blocked:
                    return jsonify({'error': reason}), status
            except Exception as e:
                logging.error(f"WAF behavior rate failed: {e}")

    @app.before_request
    async def _ids_ips_before_request():
        """IDS/IPS 签名型检测：漏洞利用载荷 / HTTP 走私 / 异常动词 / 参数洪水。

        与 WAF 互补：WAF 已拦截的请求不会到达此处（Quart 短路），故无重复计数。
        prevent 模式下命中高危/严重签名立即 403 拦截；detect 模式仅记录告警。
        """
        if not _ids._enabled():
            return
        if request.method == 'OPTIONS':
            return
        path = request.path or ''
        if path.startswith('/static/'):
            return
        client_ip = _get_client_ip()

        try:
            wl = await _whitelist_bypass(client_ip)
        except Exception:
            wl = set()
        if 'all' in wl or 'ids' in wl:
            return

        try:
            res = await _ids.ids_inspect_request(request, client_ip)
        except Exception as e:
            logging.error(f"IDS/IPS inspect failed: {e}")
            return
        if not res:
            return

        await _ids_record_event(client_ip, res)

        if res['action'] == 'block':
            if res['severity'] == 'critical' and _ids._ban_on_critical():
                await _ids_ban_ip(client_ip, f"IDS 严重签名：{res['rule']}")
            return jsonify({'error': f'Request blocked by IDS/IPS: {res["reason"]}'}), res['status']

    @app.before_request
    async def _web_filter_before_request():
        """上网行为管理：内容分类过滤（仅浏览类路径，API 接口交 WAF/IDS 处理）。

        命中封禁分类且处于 block 模式时拦截（403）；monitor 模式仅记录不拦截。
        管理员可配置豁免内容拦截（WEB_FILTER_BYPASS_ADMIN，仍记日志）。
        """
        if not _wf._enabled():
            return
        if request.method == 'OPTIONS':
            return
        path = request.path or ''
        if path.startswith('/static/'):
            return
        client_ip = _get_client_ip()
        try:
            wl = await _whitelist_bypass(client_ip)
        except Exception:
            wl = set()
        if 'all' in wl or 'webfilter' in wl:
            return
        is_admin = bool(session.get('is_admin'))
        try:
            res = _wf.wf_inspect_request(request, client_ip, is_admin)
        except Exception as e:
            logging.error(f"web_filter inspect failed: {e}")
            return
        if res and res.get('action') == 'block':
            return jsonify({'error': f'Blocked by Web Filter: {res["reason"]}'}), res['status']

    @app.before_request
    async def _csrf_protect():
        """CSRF 保护：同步令牌 + Origin/Referer 双校验"""
        if request.method in EXEMPT_CSRF_METHODS:
            return
        if is_csrf_exempt_path(request.path):
            return
        # OpenAI 兼容推理端点走 Bearer API Key，非浏览器会话请求
        if request.path.startswith('/api/chat/completions'):
            return
        if request.path.startswith('/v1/chat/completions'):
            return
        if request.path.startswith('/v1/responses'):
            return
        # OAuth 2.0 端点（token/revoke/introspect/register/device_authorization）为机到机
        # 调用，依靠 Authorization 头或 client secret 鉴权而非会话 cookie，CSRF 不适用。
        if request.path.startswith('/oauth/'):
            return
        # 任何携带 Authorization 头的程序化 API 调用（Bearer / Basic）均非浏览器会话请求。
        if request.headers.get('Authorization'):
            return
        # X-Debug-Console-Key 同理：自定义请求头不是环境凭据（浏览器不会自动附带，跨域还会触发
        # CORS 预检），故不存在 CSRF 风险。历史版本遗漏此豁免，导致 Debug Console HTTP API
        # 无法用 curl / 脚本调用（必须伪造 Origin），此处补齐。
        if request.headers.get('X-Debug-Console-Key'):
            return
        # 集群登录端点：令牌本身即强凭据（启动时随机生成，非会话 cookie），且为
        # 一次性建立会话的入口，不属于浏览器会话态写入场景，豁免 CSRF 以免无法用 curl/脚本登录。
        if request.path == '/cluster/login':
            return

        # 核心防护：浏览器会话态写请求必须携带有效的 Anti-CSRF Token（同步令牌模式）。
        if await _validate_csrf_token():
            return

        # 兜底（纵深防御）：同源 Origin/Referer 校验。无 Token 但有合法同源头也放行。
        origin = request.headers.get('Origin')
        referer = request.headers.get('Referer')
        # 兼容反向代理 / Cloudflare 隧道：代理会把客户端原始 Host 放在 X-Forwarded-Host，
        # 否则经隧道访问时浏览器 Origin（公网域名）与服务内部 Host 不一致会误判 CSRF 而 403。
        host = request.headers.get('X-Forwarded-Host', request.headers.get('Host', '')).split(':')[0]

        if not origin and not referer:
            return jsonify({'error': 'CSRF detected: missing token and missing origin/referer'}), 403

        if origin:
            o = urlparse(origin)
            if o.hostname and o.hostname != host:
                return jsonify({'error': 'CSRF detected: origin mismatch'}), 403
        elif referer:
            r = urlparse(referer)
            if r.hostname and r.hostname != host:
                return jsonify({'error': 'CSRF detected: referer mismatch'}), 403

    @app.before_request
    async def _enforce_must_change_password():
        """强制改密拦截"""
        if not session.get('must_change_password'):
            return
        allowed = {'/logout', '/login', '/api/user/change-password', '/api/change-password'}
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return
        if request.path in allowed:
            return
        return jsonify({'error': '请先修改初始密码后再继续操作（设置页 - 修改密码）',
                        'code': 'must_change_password', 'redirect': '/settings'}), 403

    @app.before_request
    async def _cors_preflight():
        """放行 OAuth 端点的 CORS 预检"""
        if request.method == 'OPTIONS' and _is_cors_endpoint(request.path):
            return '', 204

    @app.after_request
    async def _add_security_headers(response):
        """安全响应头"""
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()'
        nonce = getattr(g, 'csp_nonce', '')
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            # script-src：移除 'unsafe-inline'（XSS 核心防线），内联脚本用 nonce，
            # strict-dynamic 让 nonce 脚本动态加载的子脚本也被信任；CDN 源为旧浏览器兜底。
            f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic' https://cdn.jsdelivr.net; "
            # style-src：CSP2/3 规范——指令里出现 nonce 时 'unsafe-inline' 被忽略，
            # 曾导致全站 style="..." 内联属性被静默丢弃（86 处死样式：图表容器高度塌陷、
            # 聊天气泡对齐全废、弹窗打不开等）。拆分为 -elem / -attr：
            #   现代浏览器：<style> 元素仍强制 nonce（安全不回退），style 属性恢复生效；
            #   style-src 仅作旧浏览器回退（不带 nonce，保证 unsafe-inline 真正生效）。
            f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "style-src-attr 'unsafe-inline'; "
            f"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        # 静态资源缓存：Quart 默认对 /static/ 下发 max-age=43200（12 小时），
        # 静态文件无版本号，改短为可配置值（默认 10 分钟；0 = 不干预，恢复 Quart 默认）。
        # 显式覆盖而非"无头才补"，否则 Quart 预置的头会让本配置永远不生效。
        if STATIC_CACHE_MAX_AGE > 0 and request.path.startswith('/static/'):
            response.headers['Cache-Control'] = f'public, max-age={STATIC_CACHE_MAX_AGE}'
        # HSTS：默认跟随 SSL_ENABLED（与历史行为一致）；显式配置 HSTS_ENABLED 可强制
        # 开/关——供 Cloudflare 边缘 HTTPS + 源站 HTTP 的部署使用（纯 HTTP 响应浏览器
        # 会忽略此头，故误发无害，但仍默认跟随 SSL_ENABLED 以保持行为可预期）。
        hsts_active = HSTS_ENABLED if HSTS_ENABLED is not None else SSL_ENABLED
        if hsts_active:
            hsts_parts = [f'max-age={HSTS_MAX_AGE}']
            if HSTS_INCLUDE_SUBDOMAINS:
                hsts_parts.append('includeSubDomains')
            if HSTS_PRELOAD:
                hsts_parts.append('preload')
            response.headers['Strict-Transport-Security'] = '; '.join(hsts_parts)
        response.headers.pop('Server', None)
        response.headers.pop('server', None)
        return response

    @app.after_request
    async def _ids_ips_after_request(response):
        """IDS/IPS 行为型检测：端点枚举扫描（大量不同 404）/ 认证暴破（登录失败）。

        基于响应状态更新滑动窗口计数；prevent 模式下阈值触发时自动封禁 IP。
        """
        if not _ids._enabled():
            return response
        try:
            path = request.path or ''
            if path.startswith('/static/') or request.method == 'OPTIONS':
                return response
            client_ip = _get_client_ip()
            wl = await _whitelist_bypass(client_ip)
            if 'all' in wl or 'ids' in wl:
                return response
            res = _ids.ids_record_response(client_ip, path, response.status_code, request)
            if res and res.get('event'):
                await _ids_record_event(client_ip, res['event'])
                if res.get('ban') and _ids._mode() == 'prevent':
                    await _ids_ban_ip(client_ip, res['ban_reason'])
        except Exception as e:
            logging.error(f"IDS/IPS after_request failed: {e}")
        return response

    @app.after_request
    async def _web_filter_after_request(response):
        """上网行为管理：记录全站访问到 web_access_log（行为审计留痕）。"""
        if not _wf._enabled() or not _wf._log_all():
            return response
        try:
            path = request.path or ''
            if path.startswith('/static/') or request.method == 'OPTIONS':
                return response
            client_ip = _get_client_ip()
            user = session.get('user') or ''
            nbytes = response.content_length or 0
            await _wf.wf_record_access(request, client_ip, user,
                                       response.status_code, nbytes)
        except Exception as e:
            logging.error(f"web_filter after_request failed: {e}")
        return response

    @app.after_request
    async def _bastion_after_request(response):
        """堡垒机：记录管理路由访问（特权访问审计）。"""
        if not _bastion._enabled() or not _bastion._record_admin_routes():
            return response
        try:
            path = request.path or ''
            if request.method == 'OPTIONS':
                return response
            if _is_admin_route(path):
                client_ip = _get_client_ip()
                operator = session.get('user') or client_ip or 'unknown'
                _bastion.record_admin_access(operator, path, request.method,
                                             response.status_code, client_ip)
        except Exception as e:
            logging.error(f"bastion after_request failed: {e}")
        return response

    @app.after_request
    async def _cors_headers(response):
        """为 OAuth 端点放行跨域"""
        origin = request.headers.get('Origin')
        if origin and _is_cors_endpoint(request.path):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
            response.headers['Access-Control-Max-Age'] = '600'
            response.headers['Vary'] = 'Origin'
        return response

    @app.after_request
    async def _inject_csrf(response):
        """自动向 HTML 页面注入 CSRF 元标签、站点图标、主题切换与加载进度条"""
        if 'text/html' not in (response.headers.get('Content-Type', '') or ''):
            return response
        try:
            token = _get_csrf_token()
            _gd = response.get_data(as_text=True)
            html = _gd if isinstance(_gd, str) else await _gd
            nonce = getattr(g, 'csp_nonce', '')
            meta = ('<meta name="csrf-token" content="' + token + '">'
                    + '\n  <link rel="icon" type="image/svg+xml" sizes="any" href="/favicon.svg">'
                    + '\n  <link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48 64x64 128x128 256x256">')
            head_extra = (_THEME_BOOTSTRAP_JS + _PROGRESS_HTML).replace(
                '<script>', '<script nonce="' + nonce + '">'
            ).replace(
                '<style>', '<style nonce="' + nonce + '">'
            )
            # 只在真正的 <head> 标签后插入一次；避免命中 JS 字符串/注释里的 <head>
            # 注：暗色 CSS 不再由服务端注入静态 <style> —— 已内嵌进 bootstrap 脚本，
            # 由 JS 通过 adoptedStyleSheets 挂载/摘除（亮暗完全客户端调节）。
            head_match = re.search(r'<head\b[^>]*>', html, flags=re.IGNORECASE)
            if head_match:
                html = html[:head_match.end()] + '\n  ' + meta + '\n  ' + head_extra + html[head_match.end():]
            # 只在最后一个 </body> 前注入脚本，避免命中模板/JS 注释里的字面量
            body_pos = html.lower().rfind('</body>')
            if body_pos != -1:
                injected = (_CSRF_PATCH_JS + _EVENT_DELEGATION_JS + _THEME_UI_JS
                            + _THEME_CHARTS_JS).replace(
                    '<script>', '<script nonce="' + nonce + '">'
                )
                html = html[:body_pos] + '\n' + injected + html[body_pos:]
            response.set_data(html.encode('utf-8'))
            response.headers.pop('Content-Length', None)
        except Exception as e:
            logging.error(f"CSRF injection failed: {e}")
        return response


    # ------------------------------------------------------------------
    # 以下钩子自 __main__.py 迁移（P0-01 架构重构补齐）
    # ------------------------------------------------------------------

    @app.before_request
    async def _seq_anomaly_ja3_honeypot():
        """序列异常检测 + JA3 指纹采集 + 蜜罐会话诱捕（与 WAF/IDS 互补的「行为/追溯」层）。

        - JA3：每个请求提取并登记指纹（内存去重，首次落库+陌生告警）。
        - 序列异常：对设备/账号的接口访问顺序做 next-token 预测，异常时记录安全事件。
        - 蜜罐诱捕：已登录的蜜罐账号全程留痕，敏感管理员操作被拦截（仅记录，不真正执行）。
        """
        if request.method == 'OPTIONS':
            return
        path = request.path or ''
        if path.startswith('/static/'):
            return
        client_ip = _get_client_ip()
        ja3_hash = ''          # 由 section 1 填充，供 section 4 复用
        seq_surprise = 0.0     # 由 section 3 填充，供 section 4 复用

        # ---------- 1. JA3 指纹采集与登记 ----------
        ja3_info = None
        if getattr(_seq_configs, 'JA3_ENABLED', True):
            try:
                ja3_info = _ja3.extract_ja3(request, client_ip)
                if ja3_info.get('ja3_hash'):
                    await _ja3.register_fingerprint_async(
                        ja3_info, client_ip, _get_user_agent(),
                        user_uid='', user_name=session.get('user', '') or '')
            except Exception as e:
                logging.error(f"JA3 capture failed: {e}")
        if ja3_info:
            ja3_hash = ja3_info.get('ja3_hash') or ''

        # ---------- 1.5 JA3 维度限流（跨 IP 同指纹刷流量 / 分布式扫描）----------
        # 合成指纹（syn-）把同浏览器所有用户聚成一个哈希，默认不参与限流聚合
        # （JA3_RL_APPLY_SYNTHETIC 可开），避免 NAT/校园网场景的跨用户误报。
        if (ja3_info and ja3_info.get('ja3_hash')
                and (ja3_info.get('source') != 'synthetic'
                     or getattr(_seq_configs, 'JA3_RL_APPLY_SYNTHETIC', False))
                and getattr(_seq_configs, 'JA3_RL_ENABLED', True)):
            try:
                verdict = _ja3threat.record_request(ja3_info['ja3_hash'], client_ip)
                if verdict.get('blocked'):
                    logging.warning(f"JA3 维度限流触发: {ja3_info['ja3_hash']} "
                                    f"reason={verdict.get('reason')} "
                                    f"req={verdict.get('req_count')} ips={verdict.get('distinct_ips')}")
                    if getattr(_seq_configs, 'JA3_RL_BLOCK', False):
                        return jsonify({
                            'error': 'Too many requests from this client fingerprint'
                        }), 429
            except Exception as e:
                logging.error(f"JA3 rate limit failed: {e}")

        # ---------- 2. 蜜罐会话诱捕（is_honeypot 已在登录时写入 session，避免每请求查库）----------
        if session.get('is_honeypot'):
            hp_user = session.get('user')
            try:
                # 全程留痕
                await _honeypot.record_honeypot_activity(
                    hp_user, f"{request.method} {path}",
                    client_ip, '', detail='')
                # 敏感管理员操作拦截（仅记录，不真正执行，返回诱饵 403）
                if getattr(_seq_configs, 'HONEYPOT_TRAP_ACTIONS', True):
                    if _is_admin_route(path) or path.startswith('/api/admin'):
                        return jsonify({'error': 'Access denied (honeypot)'}), 403
            except Exception as e:
                logging.error(f"honeypot trap failed: {e}")

        # ---------- 3. 序列异常检测 ----------
        if getattr(_seq_configs, 'SEQ_ANOMALY_ENABLED', True):
            try:
                track_by = getattr(_seq_configs, 'SEQ_ANOMALY_TRACK_BY', 'account')
                if track_by == 'ip':
                    key = f"ip:{client_ip}"
                elif track_by == 'session':
                    key = f"sess:{session.get('session_id') or client_ip}"
                else:
                    key = f"acct:{session.get('user') or client_ip}"
                res = _seq.record_and_score(key, request.method, path)
                seq_surprise = res.get('surprise', 0.0)
                if res.get('anomaly'):
                    logging.warning(f"序列异常: {key} token={res.get('token')} "
                                    f"surprise={res.get('surprise')} baseline={res.get('baseline')}")
                    if getattr(_seq_configs, 'SEQ_ANOMALY_BLOCK_ON_ANOMALY', False):
                        return jsonify({'error': 'Access denied: anomalous request sequence'}), 429
            except Exception as e:
                logging.error(f"seq anomaly failed: {e}")

        # ---------- 4. bot 评分 + 同 Token 多 JA3/IP 并发检测 ----------
        if getattr(_seq_configs, 'BOT_SCORE_ENABLED', True):
            try:
                sess_id = session.get('session_id') or ''
                cf_bot = request.headers.get('cf-bot-score')
                cf_verified = (request.headers.get('cf-verified-bot', '').lower() == 'true')
                tb = _botscore.record_token_binding(
                    sess_id, ja3_hash, client_ip, session.get('user') or '')
                bot = _botscore.score_bot(ja3_info, seq_surprise, tb, cf_bot, cf_verified)
                if bot.get('is_bot'):
                    reasons = bot.get('reasons') or []
                    logging.warning(f"bot 评分高: {sess_id[:16]} score={bot['score']} "
                                    f"reasons={reasons}")
                    # 同 token 跨 JA3/跨 IP = 会话(或 token)被盗用嫌疑，强告警
                    if tb.get('shared_ja3') or tb.get('shared_ip'):
                        try:
                            from ..security import record_security_event, DeviceInfo
                            dev = DeviceInfo("unknown", "Unknown", "", "", "", "",
                                             False, [], _get_user_agent() or "")
                            await record_security_event(
                                async_db_query, '', session.get('user') or '',
                                'token_sharing', 'critical', 85,
                                [f"会话 {sess_id[:16]} 出现跨 JA3/跨 IP 复用",
                                 f"distinct_ja3={tb.get('distinct_ja3')} "
                                 f"distinct_ips={tb.get('distinct_ips')}",
                                 "可能会话/token 被盗用", f"bot_reasons={reasons}"],
                                client_ip, dev, action_taken='monitored')
                        except Exception as e:
                            logging.warning(f"token_sharing event failed: {e}")
                    if getattr(_seq_configs, 'BOT_SCORE_BLOCK', False):
                        return jsonify({'error': 'Access denied: automated client detected'}), 429
            except Exception as e:
                logging.error(f"bot score failed: {e}")

    @app.before_request
    async def _validate_session_before_request():
        """请求前：设备封禁检查(R3) + 大批量请求计数，再验证会话有效性"""
        # ---- 规则 R3：设备封禁（浏览器指纹）检查 + 批量请求计数 ----
        try:
            from ..security import (compute_request_fingerprint, is_device_banned,
                                   ban_device, record_device_request,
                                   resolve_rule_duration, get_ban_rules)
            path = request.path
            if not path.startswith('/static/') and request.method != 'OPTIONS':
                fp = compute_request_fingerprint(request)
                rules = get_ban_rules()
                dr = rules.get("bulk_request_device", {})
                if dr.get("enabled", True):
                    wl = await _whitelist_bypass(_get_client_ip())
                    bypass = ('all' in wl) or ('device_ban' in wl) or ('autoban' in wl)
                    if not bypass and await is_device_banned(async_db_query, fp):
                        return jsonify({'error': 'Device blocked: your browser fingerprint has been banned'}), 403
                    triggered, _cnt = record_device_request(
                        fp, int(dr.get("window_sec", 60)), int(dr.get("trigger_count", 1000)))
                    if triggered and not bypass:
                        kind, val = resolve_rule_duration("bulk_request_device", _cnt)
                        if kind != "never":
                            reason = f"[自动封禁-设备] {_cnt} 次请求（窗口 {dr.get('window_sec')}s）"
                            try:
                                await ban_device(async_db_query, fp, kind, val, reason)
                                logging.warning(reason)
                            except Exception as e:
                                logging.error(f"ban_device failed: {e}")
        except Exception as e:
            logging.error(f"device-ban middleware error: {e}")

        # ---- 会话有效性校验 ----
        session_id = session.get('session_id')
        username = session.get('user')

        if session_id and username:
            # 有会话ID，验证是否有效
            try:
                is_valid, sess_username = await _validate_session(session_id)
                if not is_valid or sess_username != username:
                    # 会话无效，清除登录状态
                    session.pop('user', None)
                    session.pop('session_id', None)
            except Exception as e:
                logging.error(f"Session validation error: {e}")

    @app.after_request
    async def _oauth_ns_no_cookie(response):
        """/api/oauth 是纯 Bearer 命名空间：不给第三方应用下发会话 cookie。

        上面为了复用业务函数往 session 写了用户名，若不拦住，响应会带 Set-Cookie，
        等于凭一个 access_token 换到一张完整的浏览器会话票。
        """
        if request.path == '/api/oauth' or request.path.startswith('/api/oauth/'):
            try:
                session.modified = False
            except Exception:
                pass
        return response

    @app.before_serving
    async def _load_ban_rules_on_start():
        """启动时从 config_kv 加载自定义封禁规则"""
        try:
            from .. import security
            import json as _json
            rows = await async_db_query("SELECT value FROM config_kv WHERE key='ban_rules'")
            if rows and rows[0].get('value'):
                security.set_ban_rules(_json.loads(rows[0]['value']))
                logging.info("已加载自定义封禁规则 ban_rules")
        except Exception as e:
            logging.error(f"load ban_rules on start failed: {e}")

    @app.before_serving
    async def _start_cloudflare_refresh_on_serve():
        """启动 Cloudflare 官方 IP 段定时拉取（后台线程，每日刷新并缓存）"""
        try:
            from ..cloudflare import start_cloudflare_refresh
            start_cloudflare_refresh()
            logging.info("Cloudflare IP 段定时拉取已启动")
        except Exception as e:
            logging.error(f"start cloudflare refresh failed: {e}")

    @app.before_serving
    async def _honeypot_expire_on_serve():
        """启动时清理已过期的蜜罐账号（运行期可经 Console `honeypot_expire` 再触发）。"""
        try:
            from .. import honeypot as _hp
            n = await _hp.expire_honeypots()
            if n:
                logging.info(f"启动清理 {n} 个过期蜜罐账号")
        except Exception as e:
            logging.error(f"honeypot expire on serve failed: {e}")
