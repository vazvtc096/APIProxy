# -*- coding: utf-8 -*-
"""易支付（彩虹易支付等兼容网关）适配器。

签名：MD5(按 key 字典序拼接 k=v&... ，排除 sign/sign_type/空值，末尾追加商户密钥)。

配置：
    enabled   bool
    api_url   网关根地址，如 https://pay.example.com
    pid       商户 ID
    key       商户密钥
    channel   默认支付渠道：alipay / wxpay / qqpay（默认 alipay）
    api_type  下单方式：submit（页面跳转，默认）| mapi（接口下单取 payurl）
"""
from __future__ import annotations

import hashlib
import hmac
import urllib.parse

from . import _http
from .base import PaymentProvider


def _err(code, data, fallback):
    if isinstance(data, dict):
        for k in ("msg", "message", "error", "return_msg"):
            if data.get(k):
                return str(data[k])
    return f"{fallback}（HTTP {code}）"


class EpayProvider(PaymentProvider):
    type = "epay"
    label = "易支付"

    def is_configured(self) -> bool:
        return bool(self.cfg.get("api_url") and self.cfg.get("pid") and self.cfg.get("key"))

    # ---- 签名 ----------------------------------------------------------
    def _sign(self, params: dict) -> str:
        items = sorted(
            (k, str(v)) for k, v in params.items()
            if k not in ("sign", "sign_type") and v not in (None, "")
        )
        raw = "&".join(f"{k}={v}" for k, v in items)
        return hashlib.md5((raw + str(self.cfg.get("key"))).encode("utf-8")).hexdigest()

    # ---- 下单 ----------------------------------------------------------
    async def create_order(self, request_id, amount, subject):
        channel = str(self.cfg.get("channel") or "alipay")
        params = {
            "pid": str(self.cfg.get("pid")),
            "type": channel,
            "out_trade_no": str(request_id),
            "notify_url": self.notify_url(),
            "return_url": self.return_url(request_id),
            "name": str(subject or "余额充值")[:127],
            "money": self.format_amount(amount),
        }
        api_type = str(self.cfg.get("api_type") or "submit").lower()
        base = self.cfg["api_url"].rstrip("/")

        if api_type == "mapi":
            body = dict(params)
            body["sign"] = self._sign(body)
            body["sign_type"] = "MD5"
            code, data = await _http.post_form(base + "/mapi.php", body)
            if code == 200 and isinstance(data, dict) and str(data.get("code")) == "1":
                return {
                    "order_no": str(data.get("trade_no") or request_id),
                    "pay_url": data.get("payurl") or "",
                    "qr_code": data.get("qrcode") or data.get("qrcodeimg") or "",
                    "status": "PENDING",
                    "raw": data,
                }
            return {"error": _err(code, data, "易支付下单失败")}

        params["sign"] = self._sign(params)
        params["sign_type"] = "MD5"
        pay_url = base + "/submit.php?" + urllib.parse.urlencode(params)
        return {"order_no": str(request_id), "pay_url": pay_url, "status": "PENDING", "raw": params}

    # ---- 回调 ----------------------------------------------------------
    async def verify_callback(self, data, headers=None, raw=None):
        if not isinstance(data, dict):
            return False
        sign = str(data.get("sign") or "")
        if not sign:
            return False
        return hmac.compare_digest(self._sign(data), sign.lower())

    async def parse_callback(self, data, headers=None, raw=None):
        d = data if isinstance(data, dict) else {}
        ok = await self.verify_callback(data, headers, raw)
        trade_status = str(d.get("trade_status") or "")
        paid = ok and trade_status.upper() in ("TRADE_SUCCESS", "SUCCESS")
        return {
            "ok": ok,
            "request_id": str(d.get("out_trade_no") or ""),
            "order_no": str(d.get("trade_no") or ""),
            "amount": d.get("money"),
            "status": "PAID" if paid else self.normalize_status(trade_status),
            "event": trade_status,
        }

    # ---- 查单 ----------------------------------------------------------
    async def query_order(self, request_id, order_no=None):
        url = self.cfg["api_url"].rstrip("/") + "/api.php?" + urllib.parse.urlencode({
            "act": "order",
            "pid": str(self.cfg.get("pid")),
            "key": str(self.cfg.get("key")),
            "out_trade_no": str(request_id),
        })
        code, data = await _http.get_json(url)
        if code == 200 and isinstance(data, dict):
            return {
                "status": self.normalize_status(data.get("trade_status") or data.get("status")),
                "raw": data,
            }
        return {"error": _err(code, data, "易支付查单失败")}
