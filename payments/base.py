# -*- coding: utf-8 -*-
"""支付提供方统一抽象。

每个 Provider 实现四个动作（回调相关为协程）：

    create_order(request_id, amount, subject) -> dict
        成功返回 {'order_no': str, 'pay_url': str, 'status': 'PENDING'[, 'qr_code': str]}
        失败返回 {'error': str}

    verify_callback(data, headers=None, raw=None) -> bool
        校验网关异步回调的签名 / 完整性。raw 为原始请求体（Stripe 等需要）。

    parse_callback(data, headers=None, raw=None) -> dict
        校验并解析回调，归一为统一形状：
            {'ok': bool, 'request_id': str, 'order_no': str,
             'amount': float|None, 'status': 'PAID'|..., 'event': str}
        默认实现基于 verify_callback + 常见字段名。

    query_order(request_id, order_no=None) -> dict
        返回 {'status': 'PAID'|'PENDING'|'CLOSED'|'FAILED'} 或 {'error': str}

统一状态词汇（入账只看 PAID）：
    PAID    —— 已支付成功
    PENDING —— 待支付 / 处理中
    CLOSED  —— 已关闭 / 取消 / 过期
    FAILED  —— 支付失败

配置约定：每个渠道的配置块里，`enabled` 控制启用与否；`callback_base`
（来自全局配置）用于拼装 notify_url 与 return_url，也可用 `notify_url` /
`return_url` 显式覆盖。
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod


class PaymentProvider(ABC):
    """所有支付渠道的基类。子类需覆写 type/label 与三个核心协程。"""

    #: 机器名（用于配置键、回调路径、pay_channel 记录）
    type = ""
    #: 展示名（前端按钮文案）
    label = ""

    def __init__(self, name=None, config=None):
        self.name = name or self.type
        self.cfg = dict(config or {})

    @property
    def display_name(self) -> str:
        return self.label or self.type

    # ---- 配置状态 ------------------------------------------------------
    def is_configured(self) -> bool:
        """必填配置是否齐备（子类覆写）。"""
        return True

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled")) and self.is_configured()

    def describe(self) -> dict:
        return {
            "type": self.type,
            "label": self.display_name,
            "enabled": self.enabled,
            "configured": self.is_configured(),
        }

    # ---- 回调 / 返回地址 ----------------------------------------------
    def _base_url(self) -> str:
        return str(self.cfg.get("callback_base") or "").rstrip("/")

    def notify_url(self) -> str:
        """网关异步回调本服务的地址。"""
        explicit = str(self.cfg.get("notify_url") or "").strip()
        if explicit:
            return explicit
        base = self._base_url()
        return f"{base}/api/recharge/callback/{self.type}" if base else ""

    def return_url(self, request_id=None) -> str:
        """支付完成后浏览器跳回本服务的地址。"""
        explicit = str(self.cfg.get("return_url") or "").strip()
        if explicit:
            return explicit
        base = self._base_url()
        if not base:
            return ""
        suffix = f"?rid={request_id}" if request_id else ""
        return f"{base}/dashboard/recharge{suffix}"

    # ---- 核心动作 ------------------------------------------------------
    @abstractmethod
    async def create_order(self, request_id: str, amount, subject: str) -> dict:
        raise NotImplementedError

    @abstractmethod
    async def verify_callback(self, data, headers=None, raw=None) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def query_order(self, request_id: str, order_no=None) -> dict:
        raise NotImplementedError

    # ---- 回调解析 ------------------------------------------------------
    async def parse_callback(self, data, headers=None, raw=None) -> dict:
        """校验并解析回调，归一为统一形状。子类按各自字段名覆写。"""
        d = data if isinstance(data, dict) else {}
        ok = await self.verify_callback(data, headers, raw)
        return {
            "ok": bool(ok),
            "request_id": str(d.get("out_trade_no") or d.get("merchant_order") or ""),
            "order_no": str(d.get("trade_no") or d.get("order_no") or ""),
            "amount": d.get("money") or d.get("total_amount") or d.get("amount"),
            "status": "PAID" if ok else "PENDING",
            "event": str(d.get("trade_status") or d.get("event") or ""),
        }

    # ---- 回调应答 ------------------------------------------------------
    def callback_ack(self, ok: bool = True) -> tuple:
        """网关回调的应答 (body, mimetype)。默认 JSON；网关有特殊要求时覆写。"""
        return json.dumps({"ok": bool(ok)}), "application/json"

    # ---- 工具 ----------------------------------------------------------
    @staticmethod
    def normalize_status(raw) -> str:
        """把各渠道五花八门的状态值归一为统一词汇。"""
        s = str(raw or "").strip().upper()
        if s in ("PAID", "SUCCESS", "TRADE_SUCCESS", "TRADE_FINISHED",
                 "SUCCEEDED", "COMPLETED", "CAPTURED", "SETTLEMENT"):
            return "PAID"
        if s in ("CLOSED", "TRADE_CLOSED", "CANCELED", "CANCELLED",
                 "EXPIRED", "REVOKED"):
            return "CLOSED"
        if s in ("FAILED", "FAIL", "PAYERROR", "REJECTED"):
            return "FAILED"
        return "PENDING"

    @staticmethod
    def format_amount(amount) -> str:
        return f"{float(amount):.2f}"

    @staticmethod
    def to_cents(amount) -> int:
        return int(round(float(amount) * 100))
