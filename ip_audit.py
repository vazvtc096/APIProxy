"""IP 直接访问审计模式（IP_ACCESS_MODE=audit）。

裸 IP 访问不直接拒绝，而是下发一个与访问 IP 强绑定的 Access ID，访客把 ID 交给
管理员审批；审批通过后访客通过 SSE 收到加密的临时访问 Token，换取 HttpOnly Cookie
后正常使用。全程无管理员操作时申请 1 小时自动过期。

安全设计：
- Access ID 与 IP 强绑定（ipaddress 归一化后比较），同一 IP 复用同一条申请；
- 临时 Token 服务端校验只比对 SHA-256 哈希，Cookie 为 HttpOnly + SameSite=Lax，且同样绑定 IP
  （明文仅存内存表供 SSE 下发，不落盘、不打日志，随记录清理销毁）；
- SSE 下发的 Token 经 HMAC-SHA256 流密码 + MAC 加密（传输为明文 HTTP 时防直接读走；
  真正的访问控制仍靠 IP 绑定 + 服务端哈希比对，属于纵深防御而非唯一防线）；
- 被拒绝的申请在过期前不能重复提交（冷却），pending 总量有上限防内存 DoS；
- 记录仅存内存（单进程 Hypercorn），重启即清空——等价于全员重新申请，可接受。
"""
import base64
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import time

from quart import request, jsonify, g, Response, redirect

from .configs import (
    IP_AUDIT_PENDING_TTL_HOURS, IP_AUDIT_TOKEN_TTL_HOURS, IP_AUDIT_MAX_PENDING,
)

COOKIE_NAME = "ipa_token"

# 状态机：pending → approved / denied；到期统一 expired（惰性清理）
_STATUS_PENDING = "pending"
_STATUS_APPROVED = "approved"
_STATUS_DENIED = "denied"

# Access ID 字母表：去掉 0/O/1/I/L 等易混字符，便于口头转述
_ID_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

_records = {}      # access_id -> record dict
_ip_index = {}     # 归一化 IP -> access_id
_token_index = {}  # token_sha256 -> access_id
# Token 明文仅存内存（供 SSE（重）连时下发），不落盘、不打日志，随记录清理销毁。
# 校验一律走 SHA-256 哈希比对，Cookie 泄漏数据库也拿不到明文。
_token_plain = {}  # access_id -> token 明文

# 每个来源 IP 的并发 SSE 流上限（/ip-audit/status 未认证可达，防连接堆积耗资源）
_SSE_PER_IP_LIMIT = 4
_sse_conns = {}    # 归一化 IP -> 当前流数


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def _norm_ip(ip: str) -> str:
    """IP 归一化：IPv6 收敛为 compressed 标准形，v4-mapped IPv6（::ffff:a.b.c.d）还原为 IPv4；
    非法输入原样返回。"""
    try:
        o = ipaddress.ip_address((ip or "").strip())
        if isinstance(o, ipaddress.IPv6Address) and o.ipv4_mapped:
            return o.ipv4_mapped.compressed
        return o.compressed
    except ValueError:
        return (ip or "").strip()


def _now() -> float:
    return time.time()


def _new_access_id() -> str:
    raw = "".join(secrets.choice(_ID_ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def _norm_access_id(s: str) -> str:
    return (s or "").strip().upper().replace("-", "").replace(" ", "")


def _cleanup_expired() -> None:
    now = _now()
    dead = [aid for aid, r in _records.items()
            if r["expires_at"] <= now or (r["token_expires_at"] and r["token_expires_at"] <= now)]
    for aid in dead:
        r = _records.pop(aid)
        if _token_index.get(r.get("token_hash")) == aid:
            _token_index.pop(r.get("token_hash"), None)
        _token_plain.pop(aid, None)
        if _ip_index.get(r["ip"]) == aid:
            _ip_index.pop(r["ip"], None)


def _record_public(r: dict) -> dict:
    remaining = max(0, int(r["expires_at"] - _now()))
    return {
        "access_id": r["access_id"],
        "ip": r["ip"],
        "status": r["status"],
        "created_at": int(r["created_at"]),
        "expires_in": remaining,
        "decided_by": r.get("decided_by") or "",
        "note": r.get("note") or "",
        "token_valid": bool(r["token_expires_at"] and r["token_expires_at"] > _now()),
    }


# --------------------------------------------------------------------------- #
# Token 加密（HMAC-SHA256 流密码 + MAC；密钥派生自持久密钥，重启后仍可解旧 blob）
# --------------------------------------------------------------------------- #
def _enc_key() -> bytes:
    from .configs import SESSION_SECRET, OAUTH_JWT_SECRET
    secret = SESSION_SECRET
    if not secret:
        try:
            with open(os.path.join(os.path.dirname(__file__), ".session_secret"),
                      "r", encoding="utf-8") as f:
                secret = f.read().strip()
        except Exception:
            secret = ""
    if not secret:
        secret = OAUTH_JWT_SECRET or "ip-audit-local-fallback"
    return hmac.new(secret.encode(), b"ip-audit-token-enc-v1", hashlib.sha256).digest()


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def seal_token(token: str) -> str:
    key = _enc_key()
    pt = token.encode()
    nonce = os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(pt, _keystream(key, nonce, len(pt))))
    tag = hmac.new(key, b"tag" + nonce + ct, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(nonce + ct + tag).decode()


def unseal_token(blob: str):
    """解密 grant blob；非法/被篡改返回 None。"""
    try:
        raw = base64.urlsafe_b64decode((blob or "").strip())
        if len(raw) < 16 + 32 + 1:
            return None
        nonce, ct, tag = raw[:16], raw[16:-32], raw[-32:]
        key = _enc_key()
        if not hmac.compare_digest(tag, hmac.new(key, b"tag" + nonce + ct, hashlib.sha256).digest()):
            return None
        pt = bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct))))
        return pt.decode()
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# 业务操作
# --------------------------------------------------------------------------- #
def get_or_create(ip: str):
    """按 IP 取（复用）或创建申请记录。容量满返回 None（闸门降级为普通拒绝页）。"""
    _cleanup_expired()
    nip = _norm_ip(ip)
    aid = _ip_index.get(nip)
    if aid and aid in _records:
        return _records[aid]
    pending_count = sum(1 for r in _records.values() if r["status"] == _STATUS_PENDING)
    if pending_count >= IP_AUDIT_MAX_PENDING:
        logging.warning(f"ip_audit：pending 容量满（{IP_AUDIT_MAX_PENDING}），拒绝新申请 ip={nip}")
        return None
    rec = {
        "access_id": _new_access_id(),
        "ip": nip,
        "status": _STATUS_PENDING,
        "created_at": _now(),
        "expires_at": _now() + IP_AUDIT_PENDING_TTL_HOURS * 3600,
        "decided_at": 0.0,
        "decided_by": "",
        "note": "",
        "token_hash": "",
        "token_expires_at": 0.0,
    }
    _records[rec["access_id"]] = rec
    _ip_index[nip] = rec["access_id"]
    logging.warning(f"ip_audit：新申请 {rec['access_id']} ip={nip} "
                    f"（{IP_AUDIT_PENDING_TTL_HOURS} 小时内有效）")
    _spawn_admin_notify(rec["access_id"], nip)
    return rec


def _spawn_admin_notify(access_id: str, ip: str) -> None:
    """新申请时给全部管理员发站内通知（fire-and-forget，绝不阻断请求主流程）。

    仅在有运行中事件循环时挂任务（请求闸门上下文）；同 IP 复用记录不重复通知。
    """
    try:
        import asyncio
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    async def _job():
        try:
            from .core_db import async_db_query
            from .notifications import add_notification
            rows = await async_db_query(
                "SELECT uid FROM users WHERE is_admin = 1", {})
            for r in (rows or []):
                await add_notification(
                    r["uid"] if not isinstance(r, dict) else r.get("uid", ""),
                    "IP 访问审计：新申请待审批",
                    f"来源 {ip} 正在等待审批。\nAccess ID: {access_id}\n"
                    f"有效期 {IP_AUDIT_PENDING_TTL_HOURS} 小时，逾期自动失效。",
                    level="warning", link="/admin/ip-audit")
        except Exception as e:
            logging.warning(f"ip_audit：管理员通知发送失败（不阻断）: {e}")

    loop.create_task(_job())


def find_by_id(access_id: str):
    aid = _norm_access_id(access_id)
    for k, r in _records.items():
        if _norm_access_id(k) == aid:
            return r
    return None


def approve_access(access_id: str, by: str = "console", note: str = ""):
    """批准申请：生成临时 Token（服务端仅存哈希），返回 token 明文（仅供 /grant 流程内部使用）。"""
    r = find_by_id(access_id)
    if not r:
        return None, "申请不存在"
    if r["status"] == _STATUS_DENIED:
        return None, "该申请已被拒绝，不能批准"
    if r["expires_at"] <= _now():
        return None, "申请已过期"
    token = secrets.token_urlsafe(32)
    r["status"] = _STATUS_APPROVED
    r["token_hash"] = hashlib.sha256(token.encode()).hexdigest()
    r["token_expires_at"] = _now() + IP_AUDIT_TOKEN_TTL_HOURS * 3600
    r["decided_at"] = _now()
    r["decided_by"] = by
    r["note"] = note
    _token_index[r["token_hash"]] = r["access_id"]
    _token_plain[r["access_id"]] = token
    logging.warning(f"ip_audit：申请 {r['access_id']}（ip={r['ip']}）已由 {by} 批准，"
                    f"Token 有效期 {IP_AUDIT_TOKEN_TTL_HOURS} 小时")
    return token, ""


def deny_access(access_id: str, by: str = "console", note: str = ""):
    r = find_by_id(access_id)
    if not r:
        return False, "申请不存在"
    if r["status"] == _STATUS_APPROVED:
        # 已批准的可以吊销：作废 Token 并退回 denied（冷却到原过期时间）
        if r.get("token_hash") and _token_index.get(r["token_hash"]) == r["access_id"]:
            _token_index.pop(r["token_hash"], None)
        r["token_hash"] = ""
        r["token_expires_at"] = 0.0
        _token_plain.pop(r["access_id"], None)
    r["status"] = _STATUS_DENIED
    r["decided_at"] = _now()
    r["decided_by"] = by
    r["note"] = note
    logging.warning(f"ip_audit：申请 {r['access_id']}（ip={r['ip']}）已由 {by} 拒绝/吊销")
    return True, ""


def check_token(token: str, ip: str) -> dict:
    """校验 Cookie Token：存在、未吊销、未过期、且与当前 IP 强绑定。"""
    _cleanup_expired()
    if not token:
        return {"ok": False, "reason": "no_token"}
    r = _records.get(_token_index.get(hashlib.sha256(token.encode()).hexdigest(), ""))
    if not r:
        return {"ok": False, "reason": "unknown_token"}
    if r["status"] != _STATUS_APPROVED or not r["token_expires_at"]:
        return {"ok": False, "reason": "not_approved"}
    if r["token_expires_at"] <= _now():
        return {"ok": False, "reason": "token_expired"}
    if r["ip"] != _norm_ip(ip):
        logging.warning(f"ip_audit：Token IP 不匹配（签发 {r['ip']}，当前 {_norm_ip(ip)}），拒绝")
        return {"ok": False, "reason": "ip_mismatch"}
    return {"ok": True, "record": r}


def list_records() -> list:
    _cleanup_expired()
    return [_record_public(r) for r in
            sorted(_records.values(), key=lambda r: -r["created_at"])]


def status_summary() -> dict:
    _cleanup_expired()
    return {
        "mode": "audit",
        "total": len(_records),
        "pending": sum(1 for r in _records.values() if r["status"] == _STATUS_PENDING),
        "approved": sum(1 for r in _records.values() if r["status"] == _STATUS_APPROVED),
        "denied": sum(1 for r in _records.values() if r["status"] == _STATUS_DENIED),
        "pending_ttl_hours": IP_AUDIT_PENDING_TTL_HOURS,
        "token_ttl_hours": IP_AUDIT_TOKEN_TTL_HOURS,
        "max_pending": IP_AUDIT_MAX_PENDING,
    }


# --------------------------------------------------------------------------- #
# 等待页
# --------------------------------------------------------------------------- #
def render_page(rec: dict, nonce: str) -> str:
    status = rec["status"]
    if status == _STATUS_DENIED:
        state_html = ('<p class="denied" id="state">Access denied by administrator. '
                      'You may apply again after the application expires.</p>')
    elif status == _STATUS_APPROVED:
        state_html = ('<p class="ok" id="state">Approved. Issuing access token...'
                      '</p><script nonce="' + nonce + '">location.href="/ip-audit/grant?re=1";</script>')
    else:
        state_html = ('<p class="wait" id="state"><span class="spinner"></span>'
                      'Waiting for authorization...</p>')
    expires_min = max(0, int((rec["expires_at"] - _now()) // 60))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Pending Approval</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: #0f1420; color: #dfe6f3; font-family: Consolas, Menlo, monospace; padding: 24px; }}
  .card {{ max-width: 560px; width: 100%; background: #171e2e; border: 1px solid #2a3550;
           border-radius: 12px; padding: 32px; box-shadow: 0 8px 32px rgba(0,0,0,.4); }}
  h1 {{ font-size: 18px; margin-bottom: 18px; color: #fff; }}
  p {{ line-height: 1.7; font-size: 14px; color: #b8c4da; }}
  .aid {{ display: inline-block; margin: 14px 0; padding: 10px 18px; font-size: 22px;
          letter-spacing: 2px; color: #6ee7a0; background: #0d1a12; border: 1px dashed #2e6b47;
          border-radius: 8px; user-select: all; }}
  .wait {{ color: #e8c268; }} .denied {{ color: #ef6b6b; }} .ok {{ color: #6ee7a0; }}
  .spinner {{ display: inline-block; width: 14px; height: 14px; margin-right: 8px;
              border: 2px solid #e8c268; border-top-color: transparent; border-radius: 50%;
              vertical-align: -2px; animation: spin .8s linear infinite; }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  .exp {{ margin-top: 16px; font-size: 12px; color: #6b7a97; }}
  .hint {{ margin-top: 6px; font-size: 12px; color: #6b7a97; }}
</style>
</head>
<body>
<div class="card">
  <h1>Direct Connection IP Audit</h1>
  <p>The server has direct connection IP audit mode enabled.</p>
  <p>Your Access ID:</p>
  <div class="aid">{rec['access_id']}</div>
  <p>Send this ID to the administrator for approval.</p>
  {state_html}
  <p class="exp">The application expires in {IP_AUDIT_PENDING_TTL_HOURS} hour(s).
     Remaining: <span id="ttl">{expires_min}</span> min.</p>
  <p class="hint">This page keeps watching for the administrator's decision via a secure
     event stream. The access token is bound to your IP and delivered encrypted.</p>
</div>
<script nonce="{nonce}">
(function () {{
  var aid = "{rec['access_id']}";
  var es = new EventSource('/ip-audit/status?id=' + encodeURIComponent(aid));
  function setState(txt, cls) {{
    var el = document.getElementById('state');
    el.className = cls;
    el.innerHTML = txt;
  }}
  es.addEventListener('status', function (e) {{
    try {{
      var d = JSON.parse(e.data);
      if (d.expires_in != null) {{
        var m = document.getElementById('ttl');
        if (m) m.textContent = Math.floor(d.expires_in / 60);
      }}
    }} catch (err) {{}}
  }});
  es.addEventListener('approved', function (e) {{
    es.close();
    setState('Approved. Issuing access token...', 'ok');
    try {{
      var d = JSON.parse(e.data);
      if (d.grant) location.href = '/ip-audit/grant?g=' + encodeURIComponent(d.grant);
    }} catch (err) {{}}
  }});
  es.addEventListener('denied', function () {{
    es.close();
    setState('Access denied by administrator. You may apply again after the application expires.', 'denied');
  }});
  es.addEventListener('expired', function () {{
    es.close();
    setState('Application expired. Reload to submit a new application.', 'denied');
  }});
  es.onerror = function () {{ /* 断线自动重连（EventSource 内建） */ }};
  setInterval(function () {{
    var m = document.getElementById('ttl');
    if (m && +m.textContent > 0) m.textContent = +m.textContent - 1;
  }}, 60000);
}})();
</script>
</body>
</html>"""


# --------------------------------------------------------------------------- #
# 路由（经 register_routes 挂载；/ip-audit/* 路径在闸门 audit 分支里豁免）
# --------------------------------------------------------------------------- #
def register_routes(app):
    def _mode_active() -> bool:
        """仅 audit 模式下开放审计流程；其余模式这些端点一律 404，
        防止非 audit 模式下（如 deny）被探到并制造幽灵审计记录。"""
        from . import configs
        return str(getattr(configs, "IP_ACCESS_MODE", "")).strip().lower() == "audit"

    @app.route('/ip-audit')
    async def _ip_audit_page():
        if not _mode_active():
            return jsonify({'error': 'Not found', 'code': 'not_found'}), 404
        rec = get_or_create(_client_ip())
        if rec is None:
            return jsonify({'error': 'Audit queue is full, try again later.',
                            'code': 'ip_audit_busy'}), 503
        nonce = getattr(g, 'csp_nonce', '') or secrets.token_urlsafe(16)
        return Response(render_page(rec, nonce), mimetype='text/html'), 403

    @app.route('/ip-audit/status')
    async def _ip_audit_status():
        if not _mode_active():
            return jsonify({'error': 'Not found', 'code': 'not_found'}), 404
        ip = _client_ip()
        want_id = _norm_access_id(request.args.get('id', ''))
        nip = _norm_ip(ip)
        if _sse_conns.get(nip, 0) >= _SSE_PER_IP_LIMIT:
            return jsonify({'error': 'Too many concurrent status streams.',
                            'code': 'ip_audit_busy'}), 429

        async def gen():
            _sse_conns[nip] = _sse_conns.get(nip, 0) + 1
            try:
                async for chunk in _sse_gen(ip, nip, want_id):
                    yield chunk
            finally:
                _sse_conns[nip] = max(0, _sse_conns.get(nip, 1) - 1)

        resp = Response(gen(), mimetype='text/event-stream')
        resp.headers['Cache-Control'] = 'no-cache'
        resp.headers['X-Accel-Buffering'] = 'no'
        return resp

    async def _sse_gen(ip, nip, want_id):
            last_sent = None
            deadline = _now() + (IP_AUDIT_PENDING_TTL_HOURS * 3600 + 600)  # 兜底上限
            beat = 0.0
            while _now() < deadline:
                rec = _records.get(_ip_index.get(_norm_ip(ip), ''))
                if rec is None and want_id:
                    rec = find_by_id(want_id)
                    # 只认本 IP 自己的记录，防止拿别人的 ID 偷听状态
                    if rec and rec['ip'] != _norm_ip(ip):
                        rec = None
                if rec is None:
                    yield 'event: expired\ndata: {"status":"expired"}\n\n'
                    return
                if rec['status'] == _STATUS_APPROVED and rec.get('token_hash'):
                    # 下发加密 grant（换取流程见 /ip-audit/grant）；明文仅内存暂存
                    token = _token_plain.get(rec['access_id'])
                    if token:
                        import json as _json
                        payload = _json.dumps({'grant': seal_token(token)})
                        yield f'event: approved\ndata: {payload}\n\n'
                    else:
                        yield f'event: status\ndata: {{"status":"approved"}}\n\n'
                    return
                if rec['status'] == _STATUS_DENIED:
                    yield 'event: denied\ndata: {"status":"denied"}\n\n'
                    return
                if rec['expires_at'] <= _now():
                    yield 'event: expired\ndata: {"status":"expired"}\n\n'
                    return
                snap = _record_public(rec)
                mark = (snap['status'], snap['expires_in'] // 60)
                if mark != last_sent:
                    import json as _json
                    yield f'event: status\ndata: {_json.dumps(snap)}\n\n'
                    last_sent = mark
                if _now() - beat >= 15:  # 心跳注释行，防中间层掐 idle 连接
                    yield ': ping\n\n'
                    beat = _now()
                import asyncio
                await asyncio.sleep(1)

    @app.route('/ip-audit/grant')
    async def _ip_audit_grant():
        if not _mode_active():
            return jsonify({'error': 'Not found', 'code': 'not_found'}), 404
        blob = request.args.get('g', '')
        if not blob:
            # 页面 approved 态的直接跳转：重新走 SSE 拿 grant
            return redirect('/ip-audit')
        token = unseal_token(blob)
        chk = check_token(token, _client_ip()) if token else {'ok': False}
        if not chk.get('ok'):
            return redirect('/ip-audit')
        r = chk['record']
        resp = redirect('/')
        resp.set_cookie(
            COOKIE_NAME, token,
            max_age=max(1, int(r['token_expires_at'] - _now())),
            httponly=True, samesite='Lax', path='/',
        )
        logging.warning(f"ip_audit：访客 {r['ip']} 已换取访问 Cookie（至 "
                        f"{time.strftime('%m-%d %H:%M', time.localtime(r['token_expires_at']))}）")
        return resp


def _client_ip() -> str:
    from .core_http import _get_client_ip
    return _get_client_ip()
