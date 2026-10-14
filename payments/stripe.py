# -*- coding: utf-8 -*-
"""Stripe（Checkout Session + Webhook 签名）适配器。

配置：
    enabled         bool
    secret_key      sk_live_... / sk_test_...
    webhook_secret  whsec_...（校验 webhook 用；缺失则拒绝回调）
    currency        结算币种（默认 cny；Stripe 支持 cny 时可直接用，否则改 usd 等）
"""
from __future__ import annotations

import hashlib
import hmac

from . import _http
from .base import PaymentProvider


def _err(code, data, fallback):
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if data.get("message"):
            return str(data["message"])
    return f"{fallback}（HTTP {code}）"


class StripeProvider(PaymentProvider):
    type = "stripe"
    label = "Stripe"
    API = "https://api.stripe.com"

    def is_configured(self) -> bool:
        return bool(self.cfg.get("secret_key"))

    def _headers(self) -> dict:
        return {"Authorization": "Bearer " + str(self.cfg.get("secret_key"))}

    # ---- 下单 ----------------------------------------------------------
    async def create_order(self, request_id, amount, subject):
        currency = str(self.cfg.get("currency") or "cny").lower()
        back = self._base_url() + "/dashboard/recharge"
        body = {
            "mode": "payment",
            "success_url": (self.return_url(request_id) or back),
            "cancel_url": back,
            "client_reference_id": str(request_id),
            "metadata[request_id]": str(request_id),
            "line_items[0][quantity]": 1,
            "line_items[0][price_data][currency]": currency,
            "line_items[0][price_data][unit_amount]": self.to_cents(amount),
            "line_items[0][price_data][product_data][name]": str(subject or "余额充值")[:250],
        }
        code, data = await _http.post_form(self.API + "/v1/checkout/sessions", body, self._headers())
        if code == 200 and isinstance(data, dict) and data.get("url"):
            return {"order_no": str(data.get("id")), "pay_url": data["url"],
                    "status": "PENDING", "raw": data}
        return {"error": _err(code, data, "Stripe 下单失败")}

    # ---- 回调（webhook） ----------------------------------------------
    @staticmethod
    def _verify_sig(raw, sig_header, secret) -> bool:
        payload = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw or "")
        parts = dict(p.split("=", 1) for p in str(sig_header).split(",") if "=" in p)
        t, v1 = parts.get("t"), parts.get("v1")
        if not t or not v1:
            return False
        expected = hmac.new(secret.encode("utf-8"),
                            f"{t}.{payload}".encode("utf-8"),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, v1)

    def _sig_header(self, headers) -> str:
        for k, v in (headers or {}).items():
            if str(k).lower() == "stripe-signature":
                return str(v)
        return ""

    async def verify_callback(self, data, headers=None, raw=None):
        secret = str(self.cfg.get("webhook_secret") or "")
        sig = self._sig_header(headers)
        if not secret or not sig or raw is None:
            return False
        return self._verify_sig(raw, sig, secret)

    async def parse_callback(self, data, headers=None, raw=None):
        ok = await self.verify_callback(data, headers, raw)
        d = data if isinstance(data, dict) else {}
        event = str(d.get("type") or "")
        obj = ((d.get("data") or {}).get("object") or {}) if isinstance(d.get("data"), dict) else {}
        request_id = str(obj.get("client_reference_id")
                         or (obj.get("metadata") or {}).get("request_id") or "")
        amount = None
        amt_total = obj.get("amount_total")
        if amt_total is not None:
            try:
                amount = float(amt_total) / 100.0
            except (TypeError, ValueError):
                amount = None
        paid = ok and event == "checkout.session.completed" and str(obj.get("payment_status")) == "paid"
        return {
            "ok": ok,
            "request_id": request_id,
            "order_no": str(obj.get("id") or ""),
            "amount": amount,
            "status": "PAID" if paid else "PENDING",
            "event": event,
        }

    # ---- 查单 ----------------------------------------------------------
    async def query_order(self, request_id, order_no=None):
        if not order_no:
            return {"error": "缺少会话号"}
        code, data = await _http.get_json(self.API + "/v1/checkout/sessions/" + str(order_no),
                                          self._headers())
        if code == 200 and isinstance(data, dict):
            st = "PAID" if str(data.get("payment_status")) == "paid" else self.normalize_status(data.get("status"))
            if str(data.get("status")) == "expired":
                st = "CLOSED"
            return {"status": st, "raw": data}
        return {"error": _err(code, data, "Stripe 查单失败")}
