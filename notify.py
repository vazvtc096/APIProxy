"""NapCat（OneBot 11）QQ 消息推送：余额预警 / 上游健康事件实时进 QQ。

设计要点：
- 热路径旁路：任何异常吞掉记日志，绝不影响计费/转发主链路。
- 每次发送独立 daemon 线程 + 5s 超时，调用方（prober 线程 / 余额预警协程）
  只付一次 Thread.start 的成本。
- 每次发送都重读 configs.NAPCAT（运维设置保存即热生效，无需重启）。
- 双传输模式，按 base_url 协议头自动判别：
    http://  / https://  -> OneBot 11 HTTP API（POST /send_private_msg 等）
    ws://     / wss://    -> OneBot 11 正向 WebSocket（action JSON 调用；
                              wss 的 TLS 由 NapCat 侧证书承担）
  NapCat 侧对应开启「HTTP 服务器」或「WebSocket 服务器」其一即可，
  access token 与 NapCat 侧网络配置保持一致。
"""
import logging
import threading
import uuid

import requests

from . import configs

logger = logging.getLogger(__name__)

_TIMEOUT = 5


def _targets(cfg: dict, title: str, text: str) -> list:
    """解析目标 QQ 列表 -> [(action, payload), ...]。解析失败的单项跳过。"""
    msg = f"[APIProxy] {title}\n{text}"
    out = []
    for field, action in (('user_ids', 'send_private_msg'), ('group_ids', 'send_group_msg')):
        raw = str(cfg.get(field) or '').replace('，', ',')
        for x in raw.split(','):
            x = x.strip()
            if not x:
                continue
            try:
                tid = int(float(x))
            except (TypeError, ValueError):
                continue
            payload = ({'user_id': tid} if field == 'user_ids' else {'group_id': tid})
            payload['message'] = msg
            out.append((action, payload))
    return out


def _send_http(base: str, action: str, payload: dict, token: str):
    headers = {}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    # 本机 NapCat 不走系统代理
    r = requests.post(f"{base}/{action}", json=payload, headers=headers,
                      timeout=_TIMEOUT, proxies={'http': None, 'https': None})
    body = (r.text or '')[:150]
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} {body}")
    try:
        if r.json().get('status') not in ('ok', 'async'):
            raise RuntimeError(f"OneBot reply {body}")
    except ValueError:
        pass


def _send_ws(base: str, action: str, payload: dict, token: str):
    import json as _json
    import websocket
    url = base
    if token:
        url = base + ('&' if '?' in base else '?') + 'access_token=' + token
    ws = websocket.create_connection(
        url, timeout=_TIMEOUT,
        header=[f'Authorization: Bearer {token}'] if token else None,
        # 本机 NapCat 不走系统代理
        http_proxy_host=None)
    echo = f'apx-{uuid.uuid4().hex[:8]}'
    try:
        ws.send(_json.dumps({'action': action, 'params': payload, 'echo': echo}))
        # 建连后 NapCat 会先推 lifecycle 等元事件，循环按 echo 匹配真响应
        for _ in range(5):
            resp_raw = ws.recv()
            try:
                resp = _json.loads(resp_raw)
            except (TypeError, ValueError):
                raise RuntimeError(f"non-JSON reply: {str(resp_raw)[:100]}")
            if resp.get('echo') != echo:
                continue    # meta_event / 其他事件帧，跳过
            if resp.get('status') not in ('ok', 'async'):
                raise RuntimeError(f"OneBot reply: {str(resp)[:120]}")
            return
        raise RuntimeError("no echo response received")
    finally:
        try:
            ws.close()
        except Exception:
            pass


def send_napcat(title: str, text: str) -> int:
    """投递一条 NapCat 消息（异步，立即返回）。返回排队的目标数；未启用返回 0。"""
    cfg = getattr(configs, 'NAPCAT', None) or {}
    if not cfg.get('enabled'):
        return 0
    targets = _targets(cfg, title, text)
    if not targets:
        return 0
    base = (cfg.get('base_url') or '').strip().rstrip('/')
    token = str(cfg.get('token') or '')
    use_ws = base.startswith(('ws://', 'wss://'))
    sender = _send_ws if use_ws else _send_http

    def _worker():
        for action, payload in targets:
            try:
                sender(base, action, payload, token)
            except Exception as e:
                logger.warning(f"napcat push failed ({action} via {base.split('//')[-1]}): {e}")

    threading.Thread(target=_worker, daemon=True, name='napcat-notify').start()
    return len(targets)


def notify(title: str, text: str) -> int:
    """统一入口：按当前启用的渠道投递（当前仅 NapCat）。绝不抛异常。"""
    try:
        return send_napcat(title, text)
    except Exception as e:
        logger.warning(f"notify dispatch failed: {e}")
        return 0
