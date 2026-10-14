# -*- coding: utf-8 -*-
"""PayPal（Orders v2 + Webhook 验签）适配器。

配置：
    enabled        bool
    client_id      REST 应用 Client ID
    client_secret  REST 应用 Secret
    mode           live（默认）| sandbox
    currency       结算币种（默认 USD）
"""
from __future__ import annotations

import base64

from . import _http
from .base import PaymentProvider


def _err(code, data, fallback):
    if isinstance(data, dict):
        if data.get("message"):
            return str(data["message"])
        if data.get("error_description"):
            return str(data["error_description"])
    return f"{fallback}（HTTP {code}）"


class PayPalProvider(PaymentProvider):
    type = "paypal"
    label = "PayPal"
    LIVE = "https://api-m.paypal.com"
    SANDBOX = "https://api-m.sandbox.paypal.com"

    def is_configured(self) -> bool:
        return bool(self.cfg.get("client_id") and self.cfg.get("client_secret"))

    def _api(self) -> str:
        mode = str(self.cfg.get("mode") or "live").lower()
        return self.SANDBOX if mode == "sandbox" else self.LIVE

    def _currency(self) -> str:
        return str(self.cfg.get("currency") or "USD").upper()

    # ---- 认证 ----------------------------------------------------------
    async def _access_token(self):
        raw = f"{self.cfg.get('client_id')}:{self.cfg.get('client_secret')}".encode("utf-8")
        auth = "Basic " + base64.b64encode(raw).decode("ascii")
        code, data = await _http.post_form(
            self._api() + "/v1/oauth2/token",
            {"grant_type": "client_credentials"},
            {"Authorization": auth})
        if code == 200 and isinstance(data, dict) and data.get("access_token"):
            return str(data["access_token"])
        return None

    # ---- 下单 ----------------------------------------------------------
    async def create_order(self, request_id, amount, subject):
        token = await self._access_token()
        if not token:
            return {"error": "PayPal 获取访问令牌失败"}
        back = self._base_url() + "/dashboard/recharge"
        body = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": str(request_id),
                "custom_id": str(request_id),
                "description": str(subject or "余额充值")[:127],
                "amount": {"currency_code": self._currency(), "value": self.format_amount(amount)},
            }],
            "application_context": {
                "return_url": self.return_url(request_id) or back,
                "cancel_url": back,
                "user_action": "PAY_NOW",
                "brand_name": "APIProxy",
            },
        }
        code, data = await _http.post_json(self._api() + "/v2/checkout/orders", body,
                                           {"Authorization": "Bearer " + token})
        if code in (200, 201) and isinstance(data, dict) and data.get("id"):
            pay_url = ""
            for link in (data.get("links") or []):
                if str(link.get("rel")) in ("approve", "payer-action"):
                    pay_url = str(link.get("href") or "")
                    break
            return {"order_no": str(data["id"]), "pay_url": pay_url,
                    "status": "PENDING", "raw": data}
        return {"error": _err(code, data, "PayPal 下单失败")}

    # ---- 回调（webhook 验签） -----------------------------------------
    async def verify_callback(self, data, headers=None, raw=None):
        webhook_id = str(self.cfg.get("webhook_id") or "")
        if not webhook_id or not isinstance(data, dict):
            return False
        h = {str(k).lower(): v for k, v in (headers or {}).items()}
        verify_body = {
            "auth_algo": h.get("paypal-auth-algo", ""),
            "cert_url": h.get("paypal-cert-url", ""),
            "transmission_id": h.get("paypal-transmission-id", ""),
            "transmission_sig": h.get("paypal-transmission-sig", ""),
            "transmission_time": h.get("paypal-transmission-time", ""),
            "webhook_id": webhook_id,
            "webhook_event": data,
        }
        token = await self._access_token()
        if not token:
            return False
        code, resp = await _http.post_json(
            self._api() + "/v1/notifications/verify-webhook-signature",
            verify_body, {"Authorization": "Bearer " + token})
        return (code == 200 and isinstance(resp, dict)
                and str(resp.get("verification_status")).upper() == "SUCCESS")

    async def parse_callback(self, data, headers=None, raw=None):
        d = data if isinstance(data, dict) else {}
        ok = await self.verify_callback(data, headers, raw)
        event = str(d.get("event_type") or "")
        res = d.get("resource") or {}
        if not isinstance(res, dict):
            res = {}
        request_id = str(res.get("custom_id") or "")
        if not request_id and res.get("purchase_units"):
            try:
                request_id = str(res["purchase_units"][0].get("custom_id") or "")
            except (IndexError, AttributeError):
                request_id = ""
        amount = None
        try:
            amt = res["amount"].get("value") if isinstance(res.get("amount"), dict) else None
            if amt is None and res.get("purchase_units"):
                amt = (res["purchase_units"][0].get("amount") or {}).get("value")
            if amt is not None:
                amount = float(amt)
        except (TypeError, ValueError, IndexError, KeyError, AttributeError):
            amount = None
        order_id = str(res.get("id") or "")
        paid = ok and event in ("PAYMENT.CAPTURE.COMPLETED", "CHECKOUT.ORDER.APPROVED")
        return {
            "ok": ok,
            "request_id": request_id,
            "order_no": order_id,
            "amount": amount,
            "status": "PAID" if paid else "PENDING",
            "event": event,
        }

    # ---- 查单 ----------------------------------------------------------
    async def query_order(self, request_id, order_no=None):
        if not order_no:
            return {"error": "缺少订单号"}
        token = await self._access_token()
        if not token:
            return {"error": "PayPal 获取访问令牌失败"}
        code, data = await _http.get_json(self._api() + "/v2/checkout/orders/" + str(order_no),
                                          {"Authorization": "Bearer " + token})
        if code == 200 and isinstance(data, dict):
            return {"status": self.normalize_status(data.get("status")), "raw": data}
        return {"error": _err(code, data, "PayPal 查单失败")}
