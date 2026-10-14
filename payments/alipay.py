# -*- coding: utf-8 -*-
"""支付宝（电脑网站支付 alipay.trade.page.pay，RSA2 签名）适配器。

配置：
    enabled            bool
    app_id             应用 APPID
    private_key        应用私钥（PKCS#1/PKCS#8 PEM，或裸 base64 正文）
    alipay_public_key  支付宝公钥（校验异步通知签名用，PEM 或裸 base64）
    mode               production（默认）| sandbox
    gateway            自定义网关地址（可选，覆盖 mode）
"""
from __future__ import annotations

import base64
import datetime
import json
import urllib.parse

from . import _http
from .base import PaymentProvider


def _wrap_pem(body: str, label: str) -> str:
    body = "".join(str(body).split())
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


class AlipayProvider(PaymentProvider):
    type = "alipay"
    label = "支付宝"
    GATEWAYS = {
        "production": "https://openapi.alipay.com/gateway.do",
        "sandbox": "https://openapi-sandbox.dl.alipaydev.com/gateway.do",
    }

    def is_configured(self) -> bool:
        return bool(self.cfg.get("app_id") and self.cfg.get("private_key"))

    def _gateway(self) -> str:
        gw = str(self.cfg.get("gateway") or "").strip()
        if gw:
            return gw
        mode = str(self.cfg.get("mode") or "production").lower()
        return self.GATEWAYS.get(mode, self.GATEWAYS["production"])

    # ---- 密钥 / 签名 ---------------------------------------------------
    def _private_key(self):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        pem = str(self.cfg.get("private_key") or "")
        if "BEGIN" not in pem:
            pem = _wrap_pem(pem, "RSA PRIVATE KEY")
        return load_pem_private_key(pem.encode("utf-8"), password=None)

    def _public_key(self):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pem = str(self.cfg.get("alipay_public_key") or "")
        if not pem:
            return None
        if "BEGIN" not in pem:
            pem = _wrap_pem(pem, "PUBLIC KEY")
        return load_pem_public_key(pem.encode("utf-8"))

    @staticmethod
    def _payload(params: dict) -> str:
        items = sorted(
            (k, str(v)) for k, v in params.items()
            if k not in ("sign", "sign_type") and v not in (None, "")
        )
        return "&".join(f"{k}={v}" for k, v in items)

    def _sign(self, params: dict) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        raw = self._payload(params)
        sig = self._private_key().sign(raw.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        return base64.b64encode(sig).decode("ascii")

    # ---- 下单 ----------------------------------------------------------
    async def create_order(self, request_id, amount, subject):
        biz = {
            "out_trade_no": str(request_id)[:64],
            "total_amount": self.format_amount(amount),
            "subject": str(subject or "余额充值")[:256],
            "product_code": "FAST_INSTANT_TRADE_PAY",
        }
        params = {
            "app_id": str(self.cfg.get("app_id")),
            "method": "alipay.trade.page.pay",
            "format": "JSON",
            "charset": "utf-8",
            "sign_type": "RSA2",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "notify_url": self.notify_url(),
            "return_url": self.return_url(request_id),
            "biz_content": json.dumps(biz, ensure_ascii=False, separators=(",", ":")),
        }
        try:
            params["sign"] = self._sign(params)
        except Exception as e:
            return {"error": f"支付宝签名失败: {e}"}
        pay_url = self._gateway() + "?" + urllib.parse.urlencode(params)
        return {"order_no": str(request_id), "pay_url": pay_url, "status": "PENDING", "raw": params}

    # ---- 回调 ----------------------------------------------------------
    async def verify_callback(self, data, headers=None, raw=None):
        if not isinstance(data, dict):
            return False
        sign = str(data.get("sign") or "")
        if not sign:
            return False
        pub = self._public_key()
        if pub is None:
            return False
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        raw_str = self._payload(data)
        is_rsa2 = str(data.get("sign_type") or "RSA2").upper() == "RSA2"
        digest = hashes.SHA256() if is_rsa2 else hashes.SHA1()
        try:
            pub.verify(base64.b64decode(sign), raw_str.encode("utf-8"),
                       padding.PKCS1v15(), digest)
            return True
        except Exception:
            return False

    async def parse_callback(self, data, headers=None, raw=None):
        d = data if isinstance(data, dict) else {}
        ok = await self.verify_callback(data, headers, raw)
        trade_status = str(d.get("trade_status") or "")
        paid = ok and trade_status.upper() in ("TRADE_SUCCESS", "TRADE_FINISHED")
        return {
            "ok": ok,
            "request_id": str(d.get("out_trade_no") or ""),
            "order_no": str(d.get("trade_no") or ""),
            "amount": d.get("total_amount"),
            "status": "PAID" if paid else self.normalize_status(trade_status),
            "event": trade_status,
        }

    # ---- 查单 ----------------------------------------------------------
    async def query_order(self, request_id, order_no=None):
        biz = {"out_trade_no": str(request_id)[:64]}
        params = {
            "app_id": str(self.cfg.get("app_id")),
            "method": "alipay.trade.query",
            "format": "JSON",
            "charset": "utf-8",
            "sign_type": "RSA2",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "biz_content": json.dumps(biz, ensure_ascii=False, separators=(",", ":")),
        }
        try:
            params["sign"] = self._sign(params)
        except Exception as e:
            return {"error": f"支付宝签名失败: {e}"}
        code, data = await _http.post_form(self._gateway(), params)
        if code == 200 and isinstance(data, dict):
            resp = data.get("alipay_trade_query_response") or {}
            return {"status": self.normalize_status(resp.get("trade_status")), "raw": data}
        return {"error": f"支付宝查单失败（HTTP {code}）"}
