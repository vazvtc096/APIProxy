# -*- coding: utf-8 -*-
"""analogBank 商户支付网关客户端（ab.rsmc.cc.cd）。

签名规则（与银行侧 analogbank/routes/merchant.py 完全一致）：
    sign = HMAC_SHA256(api_secret, "k1=v1&k2=v2...")
    参数按 key 字典序、值 str() 化、排除 sign 本身与 None；请求须带 timestamp（±300s）。

接口：
    POST /api/merchant/order         下单（同商户同 merchant_order 幂等）
    POST /api/merchant/order/query   查单
    POST <callback_url>              银行异步回调（payment.success / payment.expired）
"""
import asyncio
import hashlib
import hmac
import json
import logging
import time
import urllib.error
import urllib.request

from .configs import BANK_PAY, BANK_PAY_ENABLED

logger = logging.getLogger(__name__)


def bank_pay_enabled() -> bool:
    return BANK_PAY_ENABLED


def pay_sign(secret: str, params: dict) -> str:
    """与银行侧同源的签名函数。"""
    items = sorted((k, str(v)) for k, v in params.items() if k != "sign" and v is not None)
    qs = "&".join(f"{k}={v}" for k, v in items)
    return hmac.new(secret.encode("utf-8"), qs.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_callback(payload: dict) -> bool:
    """校验银行回调签名。payload 含 event/order_no/merchant_order/amount/status/paid_at/sign。"""
    secret = BANK_PAY["api_secret"]
    sign = payload.get("sign") or ""
    if not sign:
        return False
    return hmac.compare_digest(pay_sign(secret, payload), sign)


def _post(path: str, body: dict, timeout: float = 15.0) -> tuple:
    """同步 POST JSON，返回 (status_code, dict|None)。"""
    url = BANK_PAY["api_url"] + path
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "APIProxy-BankPay/1.0"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as e:
        code = e.code
        raw = e.read() or b""
    except Exception as e:
        return 0, {"error": f"请求银行网关失败: {e}"}
    try:
        return code, json.loads(raw.decode("utf-8"))
    except Exception:
        return code, None


async def create_order(merchant_order: str, amount, title: str) -> dict:
    """创建支付订单。返回银行应答 dict（含 order_no/pay_url/status）。

    异常/失败时返回 {'error': ...}；同 merchant_order 重复下单由银行幂等处理。
    """
    if not bank_pay_enabled():
        return {"error": "analogBank 支付通道未启用"}
    params = {
        "api_key": BANK_PAY["api_key"],
        "merchant_order": str(merchant_order)[:64],
        "amount": str(amount),
        "title": str(title or "余额充值")[:64],
        "callback_url": BANK_PAY["callback_url"],
        "timestamp": str(int(time.time())),
    }
    params["sign"] = pay_sign(BANK_PAY["api_secret"], params)
    code, data = await asyncio.to_thread(_post, "/api/merchant/order", params)
    if code == 200 and isinstance(data, dict) and data.get("order_no"):
        return data
    logger.warning("bank create_order failed: http=%s resp=%s", code, data)
    return {"error": (data or {}).get("error") if isinstance(data, dict) else None
            or f"银行网关返回异常（HTTP {code}）"}


async def query_order(merchant_order: str) -> dict:
    """按 merchant_order 查单。返回 {'status': ...} 或 {'error': ...}。"""
    if not bank_pay_enabled():
        return {"error": "analogBank 支付通道未启用"}
    params = {
        "api_key": BANK_PAY["api_key"],
        "merchant_order": str(merchant_order)[:64],
        "timestamp": str(int(time.time())),
    }
    params["sign"] = pay_sign(BANK_PAY["api_secret"], params)
    code, data = await asyncio.to_thread(_post, "/api/merchant/order/query", params)
    if code == 200 and isinstance(data, dict):
        return data
    return {"error": (data or {}).get("error") if isinstance(data, dict) else None
            or f"银行网关返回异常（HTTP {code}）"}
