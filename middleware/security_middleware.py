"""中间件注册：在 Quart app 上注册全局 before_request / after_request 处理器。

包括：WAF 规则检查、CSRF 保护、强制改密拦截、安全响应头、CORS、CSRF 注入。
"""
import logging
import secrets
import time
from urllib.parse import urlparse
from quart import request, session, jsonify, g

from ..app import app
from ..core import (
    _get_csrf_token, _validate_csrf_token, _get_client_ip,
    async_db_query, _whitelist_bypass, _validate_session,
    EXEMPT_CSRF_METHODS, EXEMPT_CSRF_PATHS, _CSRF_PATCH_JS,
)
from ..configs import SSL_ENABLED
from .. import waf as _waf
from .. import ids_ips as _ids
from .. import web_filter as _wf
from .. import bastion as _bastion


# 事件委托脚本：替代内联 onclick/oninput 等内联事件处理器（CSP 移除 'unsafe-inline' 后，
# 内联事件处理器会被浏览器拒绝执行）。约定：
#   data-action="fn"                          → click 时调用 window.fn()（this=元素）
#   data-action="fn" data-args="a\x01b"       → 传参 window.fn(a, b)
#   data-action="fn" data-on="input|..."      → 指定事件类型（默认 click）
#   data-arg-this                             → 追加元素本身作为参数（排在 data-args 之后）
#   data-arg-value                            → 追加元素 .value 作为参数
#   data-arg-event                            → 追加事件对象作为参数
#   data-then="fn2" data-then-args="a"        → 主 action 之后依次调用 fn2(a)
#   data-stop                                 → stopPropagation（原 onclick="event.stopPropagation()"）
#   data-prevent                              → preventDefault（原 onsubmit="return false"）
#   data-nav="/path"                          → 点击跳转（替代 onclick="location.href='...'"）
_EVENT_DELEGATION_JS = """<script>
(function () {
  function run(el, e, action) {
    if (!action) return undefined;
    var fn = window[action];
    if (typeof fn !== 'function') return undefined;
    var args = [];
    if (el.hasAttribute('data-arg-event')) args.push(e);
    if (el.hasAttribute('data-args')) args = args.concat(el.getAttribute('data-args').split('\\u0001'));
    if (el.hasAttribute('data-arg-this')) args.push(el);
    if (el.hasAttribute('data-arg-value')) args.push(el.value);
    var r = fn.apply(el, args);
    if (el.hasAttribute('data-then')) {
      var fn2 = window[el.getAttribute('data-then')];
      if (typeof fn2 === 'function') {
        var a2 = el.hasAttribute('data-then-args') ? el.getAttribute('data-then-args').split('\\u0001') : [];
        fn2.apply(el, a2);
      }
    }
    return r;
  }
  function dispatch(e) {
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
    if (el.hasAttribute('data-prevent') || r === false) e.preventDefault();
  }
  document.addEventListener('click', function (e) {
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

    @app.before_request
    async def _generate_csp_nonce():
        """为每个请求生成唯一 CSP nonce（供内联 <script>/<style> 使用）。

        每次请求随机生成，攻击者无法预知，从而在移除 'unsafe-inline'
        后仍允许受信的内联脚本/样式执行。
        """
        g.csp_nonce = secrets.token_urlsafe(16)

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
        if request.path in EXEMPT_CSRF_PATHS:
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
        # X-RCON-Key 同理：自定义请求头不是环境凭据（浏览器不会自动附带，跨域还会触发
        # CORS 预检），故不存在 CSRF 风险。历史版本遗漏此豁免，导致 RCON HTTP API
        # 无法用 curl / 脚本调用（必须伪造 Origin），此处补齐。
        if request.headers.get('X-RCON-Key'):
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
            # style-src：内联 <style> 已 nonce 化；'unsafe-inline' 暂保留以兼容
            # 168 处 style="..." 内联样式属性（CSS 注入危害低，迁移到 class 为后续项）。
            f"style-src 'self' 'nonce-{nonce}' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        if SSL_ENABLED:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
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
        """自动向 HTML 页面注入 CSRF 元标签与全局 fetch 补丁"""
        if 'text/html' not in (response.headers.get('Content-Type', '') or ''):
            return response
        try:
            token = _get_csrf_token()
            _gd = response.get_data(as_text=True)
            html = _gd if isinstance(_gd, str) else await _gd
            meta = '<meta name="csrf-token" content="' + token + '">'
            if '<head>' in html:
                html = html.replace('<head>', '<head>\n  ' + meta, 1)
            elif '<HEAD>' in html:
                html = html.replace('<HEAD>', '<HEAD>\n  ' + meta, 1)
            if '</body>' in html or '</BODY>' in html:
                nonce = getattr(g, 'csp_nonce', '')
                injected = (_CSRF_PATCH_JS + _EVENT_DELEGATION_JS).replace(
                    '<script>', '<script nonce="' + nonce + '">'
                )
                if '</body>' in html:
                    html = html.replace('</body>', injected + '\n</body>', 1)
                else:
                    html = html.replace('</BODY>', injected + '\n</BODY>', 1)
            response.set_data(html.encode('utf-8'))
            response.headers.pop('Content-Length', None)
        except Exception as e:
            logging.error(f"CSRF injection failed: {e}")
        return response


    # ------------------------------------------------------------------
    # 以下钩子自 __main__.py 迁移（P0-01 架构重构补齐）
    # ------------------------------------------------------------------

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
