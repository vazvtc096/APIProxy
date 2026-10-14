"""共享工具函数与状态。
包含数据库辅助、限流、输入净化、管理员检查、费用计算等跨模块共用功能。
"""
import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
import uuid
import sqlite3
import os
from typing import Literal, Dict
from quart import request, session, jsonify, redirect, g
from .configs import DB_PATH, SSL_ENABLED, DEBUG_CONSOLE_ENABLED
from .apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from . import upstreams
from . import configs
from . import db
from .constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from .cloudflare import get_client_ip as _cf_get_client_ip
from . import waf as _waf

# ── 原生加速器桥接（C/C++ 多语言支柱）──
# 优先使用编译好的原生库（FNV-1a 哈希 / 常量时间比较）；缺失或自测失败时
# 回退纯 Python / 标准库，保证无 C 工具链的机器也能正常运行。
try:
    from .native import constant_time_compare, fnv1a_64, native_available as _NATIVE_AVAILABLE
except Exception:  # noqa: BLE001
    _NATIVE_AVAILABLE = False
    constant_time_compare = secrets.compare_digest  # 标准库常量时间比较，安全等价

    def fnv1a_64(data):
        """纯 Python 回退：FNV-1a 64-bit 哈希。"""
        _d = data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8")
        _h = 14695981039346656037
        for _b in bytes(_d):
            _h ^= _b
            _h = (_h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
        return _h

# star 导入白名单：显式列出下划线前缀符号，
# 否则 `from ..core import *` 会静默跳过它们（PEP 8 默认行为）。
__all__ = [
    'EXEMPT_CSRF_METHODS', 'EXEMPT_CSRF_PATHS', 'EXEMPT_CSRF_PREFIXES', 'CSRF_TOKEN_LEN', '_get_csrf_token',
    '_validate_csrf_token', '_CSRF_PATCH_JS', 'MIN_PASSWORD_LENGTH', 'MAX_USERNAME_LENGTH',
    'MAX_ACTIVE_SESSIONS', 'DEFAULT_MAX_SESSIONS', 'SESSION_EXPIRE_DAYS', 'RATE_LIMITS',
    '_init_rate_limit_table', '_cleanup_rate_limits_sync', '_get_rate_limit_key',
    '_check_rate_limit', '_get_rate_limit_retry_after', '_DANGEROUS_TAGS', '_DANGEROUS_ATTRS',
    '_JAVASCRIPT_URI', '_sanitize_user_content', '_USERNAME_ALLOWED', '_is_safe_username',
    'UserTaskManager', '_get_conn', 'async_db_query', '_record_usage_log',
    'async_db_update_balence', '_atomic_pre_deduct_balence', '_atomic_force_deduct_balence',
    '_atomic_add_balence', '_is_admin', '_require_admin', '_generate_request_id',
    '_get_user_by_uid', '_is_user_banned', 'task_manager', '_calculate_cost',
    '_init_sessions_table', '_create_session_sync', '_validate_session_sync',
    '_delete_session_sync', '_get_user_sessions_sync', '_get_user_session_count_sync',
    '_kick_oldest_session_sync', '_cleanup_expired_sessions_sync', '_init_debug_console_table',
    '_legacy_debug_console_config_key',
    '_get_debug_console_key_sync', '_refresh_debug_console_key_sync', '_verify_debug_console_key_sync', '_get_debug_console_key',
    '_refresh_debug_console_key', '_verify_debug_console_key', '_create_session', '_validate_session',
    '_delete_session', '_get_user_sessions', '_get_user_session_count', '_kick_oldest_session',
    '_generate_debug_console_key_sync', '_validate_debug_console_key_sync', '_list_debug_console_keys_sync',
    '_revoke_debug_console_key_sync', '_execute_debug_console_command_sync', '_generate_debug_console_key',
    '_validate_debug_console_key', '_list_debug_console_keys', '_revoke_debug_console_key', '_execute_debug_console_command',
    'DEBUG_CONSOLE_KEY_LENGTH', '_get_client_ip', '_get_user_agent', '_record_login_log', '_ip_in_cidr',
    '_whitelist_bypass', '_neg_time_key', 'MODELS_CACHE_TTL', '_MODELS_CACHE',
    '_normalize_upstream_payload', '_concat_text_parts', '_responses_input_to_messages',
    '_chat_to_responses', '_sse_response_event', '_oauth_redirect_error',
    '_is_absolute_http_uri', '_oauth_ensure_user', 'OAUTH_API_RESOURCES', '_scope_satisfied',
    '_ALLOWED_SECTIONS', '_debug_console_auth', '_start_debug_console_server_thread', '_usage_daily',
    '_usage_daily_by_model', 'DOCS_DIR',
    '_doc_meta', '_scan_docs', '_load_doc', '_is_debug_console_authenticated',
    '_debug_console_verify_admin_credentials', 'request', 'session', 'jsonify', 'redirect', 'pricing',
    'oauth', 'upstreams', 'configs', 'DB_PATH', 'SSL_ENABLED', 'DEBUG_CONSOLE_ENABLED', 'APIKey',
    'hash_password', 'verify_password', 'generate_uid', '_get_user_by_name',
    '_verify_user_password', 'logging', 'asyncio', 'json', 'time', 'os', 're', 'secrets',
    'uuid', 'hashlib', 'sqlite3', 'urlencode', 'urlparse',
    'init_integrations',
    # 自 hooks / social 转出，供路由模块 star 导入
    'fire_event', '_get_current_user', '_require_login', '_generate_post_id',
    '_generate_message_id', '_generate_transaction_id',
]

import ipaddress as _ipaddress
from urllib.parse import urlencode, urlparse
from . import pricing
from . import oauth
from .hooks import fire_event
from .social import (_get_current_user, _require_login, _generate_post_id,
                     _generate_message_id, _generate_transaction_id)
# 阶段 2 拆分：纯函数下沉到独立模块，此处重新导出以保持 `core.xxx` 兼容
from .core_security_utils import (_DANGEROUS_TAGS, _DANGEROUS_ATTRS, _JAVASCRIPT_URI,
                                  _sanitize_user_content, _USERNAME_ALLOWED, _is_safe_username,
                                  MIN_PASSWORD_LENGTH, MAX_USERNAME_LENGTH)
from .core_proxy_utils import (_neg_time_key, _normalize_upstream_payload, _concat_text_parts,
                               _responses_input_to_messages, _chat_to_responses, _sse_response_event)
from .core_net_utils import _ip_in_cidr, _is_absolute_http_uri, _scope_satisfied
from .core_db import _get_conn, async_db_query
from .core_http import _get_client_ip, _get_user_agent
from .core_rate_limit import (RATE_LIMITS, _init_rate_limit_table, _cleanup_rate_limits_sync,
                              _get_rate_limit_key, _check_rate_limit, _check_rate_limit_redis,
                              _check_rate_limit_sqlite, _get_rate_limit_retry_after)
from .core_session import (SESSION_EXPIRE_DAYS, _init_sessions_table, _create_session_sync,
                           _validate_session_sync, _delete_session_sync, _get_user_sessions_sync,
                           _get_user_session_count_sync, _kick_oldest_session_sync,
                           _cleanup_expired_sessions_sync, _create_session, _validate_session,
                           _delete_session, _get_user_sessions, _get_user_session_count,
                           _kick_oldest_session)
from .core_billing import (_record_usage_log, async_db_update_balence, _atomic_pre_deduct_balence,
                           _atomic_force_deduct_balence, _atomic_add_balence, _calculate_cost)
from .core_auth import (_is_admin, _require_admin, _generate_request_id, _get_user_by_uid,
                        _is_user_banned)
from .core_tasks import UserTaskManager, task_manager
from .core_debug_console import (DEBUG_CONSOLE_KEY_LENGTH, _init_debug_console_table, _legacy_debug_console_config_key,
                        _get_debug_console_key_sync, _refresh_debug_console_key_sync, _verify_debug_console_key_sync,
                        _get_debug_console_key, _refresh_debug_console_key, _verify_debug_console_key,
                        _generate_debug_console_key_sync, _validate_debug_console_key_sync, _list_debug_console_keys_sync,
                        _revoke_debug_console_key_sync, _execute_debug_console_command_sync, _generate_debug_console_key,
                        _validate_debug_console_key, _list_debug_console_keys, _revoke_debug_console_key,
                        _execute_debug_console_command, _debug_console_auth, _start_debug_console_server_thread,
                        _is_debug_console_authenticated, _debug_console_verify_admin_credentials)
from .core_oauth import (_oauth_redirect_error, _oauth_ensure_user,
                         OAUTH_API_RESOURCES, _ALLOWED_SECTIONS)
from .core_docs import (_usage_daily, _usage_daily_by_model, DOCS_DIR, _doc_meta, _scan_docs, _load_doc)


# ---------- CSRF ----------
EXEMPT_CSRF_METHODS = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}
EXEMPT_CSRF_PATHS = {'/api/password-reset/request', '/api/password-reset/confirm', '/register', '/login'}
# 前缀豁免：服务端对服务端回调，路径含动态段（支付渠道名）
EXEMPT_CSRF_PREFIXES = ('/api/recharge/callback/',)
CSRF_TOKEN_LEN = 32

def _get_csrf_token() -> str:
    """返回当前会话的 CSRF 令牌"""
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_hex(CSRF_TOKEN_LEN)
        session['csrf_token'] = token
    return token

async def _validate_csrf_token() -> bool:
    """校验请求携带的 CSRF 令牌"""
    expected = session.get('csrf_token')
    if not expected:
        return False
    provided = request.headers.get('X-CSRF-Token')
    if not provided:
        ctype = (request.headers.get('Content-Type') or '').lower()
        try:
            if 'application/json' in ctype:
                j = await request.get_json(silent=True)
                if isinstance(j, dict):
                    provided = j.get('csrf_token')
            elif 'form' in ctype:
                provided = (await request.form).get('csrf_token')
        except Exception:
            provided = None
    if not provided:
        return False
    return constant_time_compare(expected, provided)

_CSRF_PATCH_JS = '''<script>\n(function(){
  var m = document.querySelector('meta[name="csrf-token"]');
  var t = m ? m.getAttribute('content') : '';
  if (!t || !window.fetch) return;
  var _f = window.fetch.bind(window);
  window.fetch = function(u, o){
    o = o || {};
    var method = (o.method || (typeof u === 'object' && u.method) || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      if (o.headers instanceof Headers) { o.headers.set('X-CSRF-Token', t); }
      else { o.headers = o.headers || {}; o.headers['X-CSRF-Token'] = t; }
    }
    return _f(u, o);
  };
})();
</script>'''

# ---------- 安全常量 ----------

# ---------- 多设备登录限制 ----------
MAX_ACTIVE_SESSIONS = 5
DEFAULT_MAX_SESSIONS = 1

# ---------- Debug Console 密钥 ----------


# ---------- 请求频率限制 ----------
# （限流逻辑与 RATE_LIMITS 已下沉到 core_rate_limit.py，见文件顶部重新导入）

# ---------- 输入净化 ----------
# ---------- 输入净化（防御存储型 XSS，纵深防御配合 CSP） ----------
# （内容净化 / 用户名校验纯函数已下沉到 core_security_utils.py，见文件顶部重新导入）





# ---------- 数据库辅助函数 ----------


# ---------- 管理员权限检查 ----------


# ---------- 充值请求辅助函数 ----------


# ---------- 封禁检查 ----------


# ---------- 全局任务管理器实例 ----------


# ---------- 费用计算函数（查表法，O(n) 极速） ----------
# 字符->单价 的 token 估算表仍在 constants.py（token_price_config.json）；
# 「每百万 token 多少钱」这一乘子改由 pricing.resolve_price 解析（支持按时段 / 绑定上游 Key）。


# ========== 从 __main__.py 迁移的函数 ==========





# ============================================================================
# 以下代码自 __main__.py 迁移（P0-01 架构重构）
# ============================================================================


# （_get_client_ip / _get_user_agent 已下沉到 core_http.py，见文件顶部重新导入）


async def _record_login_log(user_uid, user_name, ip, user_agent, status, reason='', ja3_hash=''):
    """记录登录日志"""
    try:
        await async_db_query(
            "INSERT INTO login_logs (user_uid, user_name, login_ip, user_agent, status, reason, ja3_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_uid or '', user_name or '', ip, user_agent, status, reason, ja3_hash or '')
        )
    except Exception as e:
        logging.error(f"Record login log failed: {e}")


# （_ip_in_cidr 已下沉到 core_net_utils.py，见文件顶部重新导入）


async def _whitelist_bypass(client_ip: str) -> set:
    """返回白名单 IP 应绕过的拦截类别集合；空集合表示未匹配白名单。

    类别：blacklist（IP黑名单）、autoban（安全自动封禁）、
          account_ban（账号封禁）、ratelimit（登录限流）。
    bypass 字段为 'all' 时表示绕过全部拦截。

    性能：中间件同一请求内最多 5 处调用本函数（WAF/IDS/web_filter/设备封禁），
    此处做请求级缓存，一次请求只查一次库（g 在请求结束时自动销毁，无跨请求污染）。
    """
    if not client_ip or client_ip == 'unknown':
        return set()
    try:
        cached = getattr(g, '_whitelist_bypass_cache', None)
    except RuntimeError:
        cached = None  # 无请求上下文（后台任务/调度器等），直接走查询
    if cached is not None and client_ip in cached:
        return set(cached[client_ip])

    result = await _whitelist_bypass_query(client_ip)

    if cached is not None:
        cached[client_ip] = frozenset(result)
    return result


async def _whitelist_bypass_query(client_ip: str) -> set:
    """实际查询 ip_whitelist（由 _whitelist_bypass 包裹请求级缓存）。"""
    try:
        rows = await async_db_query("SELECT ip, bypass FROM ip_whitelist")
    except Exception:
        return set()
    matched = set()
    for r in (rows or []):
        if _ip_in_cidr(client_ip, r.get('ip') or ''):
            scope = (r.get('bypass') or 'all').strip().lower()
            if scope == 'all':
                return {'all'}
            for part in scope.split(','):
                part = part.strip()
                if part:
                    matched.add(part)
    return matched


# （代理辅助纯函数 _neg_time_key/_normalize_upstream_payload/_concat_text_parts/
#   _responses_input_to_messages/_chat_to_responses/_sse_response_event 已下沉到
#   core_proxy_utils.py，见文件顶部重新导入）

MODELS_CACHE_TTL = 300


_MODELS_CACHE = {'ts': 0.0, 'data': None}






# ============================================================================
# 集成初始化
# ============================================================================

def init_integrations() -> None:
    """初始化 hooks / announcements 模块的依赖注入。

    原 __main__.py 在模块级直接调用：
        _hooks.init_hooks(async_db_query, _generate_message_id)
        _ann.init_announcements(async_db_query, _generate_message_id)
    重构后收敛为显式函数，由入口在蓝图注册后调用，避免循环导入与加载顺序问题。
    """
    from . import hooks as _hooks
    from . import announcements as _ann
    from .social import _generate_message_id

    try:
        _hooks.init_hooks(async_db_query, _generate_message_id)
        logging.info("Hooks module initialized")
    except Exception as e:
        logging.error(f"init_hooks failed: {e}")

    try:
        _ann.init_announcements(async_db_query, _generate_message_id)
        logging.info("Announcements module initialized")
    except Exception as e:
        logging.error(f"init_announcements failed: {e}")

    try:
        from . import notifications as _ntf
        _ntf.init_notifications(async_db_query)
        logging.info("Notifications module initialized")
    except Exception as e:
        logging.error(f"init_notifications failed: {e}")

    try:
        from . import system_users as _su
        _su.init_system_users(async_db_query)
        logging.info("System users module initialized")
    except Exception as e:
        logging.error(f"init_system_users failed: {e}")
