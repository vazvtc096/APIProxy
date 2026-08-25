"""核心计费与封禁逻辑单元测试（纯函数，无 IO）。"""
import asyncio
import datetime

import pytest

from APIProxy import core


def _expected(content: str, type_: str) -> float:
    """按源码同款查表逻辑计算期望值，避免硬编码单价魔法数。"""
    total = 0.0
    for ch in content:
        code = ord(ch)
        total += core.CHAR_PRICE_LOOKUP[code] if code < 0x10000 else core.UNEXCEPT_CHAR
    in_price, out_price = core.pricing.resolve_price("deepseek", None)
    money = in_price if type_ == "input" else out_price
    return round(total / 1_000_000.0 * money, 6)


def test_calculate_cost_empty_content():
    # 空字符串不应产生费用
    assert core._calculate_cost("", "deepseek", "input") == 0.0


def test_calculate_cost_basic():
    content = "hello"
    assert core._calculate_cost(content, "deepseek", "input") == _expected(content, "input")
    assert core._calculate_cost(content, "deepseek", "input") > 0


def test_calculate_cost_input_vs_output_uses_price_ratio():
    content = "x" * 100
    inp = core._calculate_cost(content, "deepseek", "input")
    out = core._calculate_cost(content, "deepseek", "output")
    assert inp == _expected(content, "input")
    assert out == _expected(content, "output")
    in_price, out_price = core.pricing.resolve_price("deepseek", None)
    if out_price != in_price:
        assert out > inp


def test_calculate_cost_non_bmp_char_uses_unexcept():
    # 非 BMP 字符（emoji）超出 0xFFFF，走 UNEXCEPT_CHAR 兜底
    content = "\U0001F600"  # 😀
    assert core._calculate_cost(content, "deepseek", "input") == _expected(content, "input")


def test_is_user_banned_not_banned():
    res = asyncio.run(core._is_user_banned({"is_banned": 0}))
    assert res == (False, "")


def test_is_user_banned_permanent():
    res = asyncio.run(core._is_user_banned({"is_banned": 1, "ban_reason": "违规"}))
    banned, msg = res
    assert banned is True
    assert "违规" in msg


def test_is_user_banned_expired():
    past = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    res = asyncio.run(core._is_user_banned({"is_banned": 1, "ban_reason": "过期", "ban_expire_at": past}))
    banned, msg = res
    assert banned is False
    assert msg == ""


def test_is_user_banned_future():
    future = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    res = asyncio.run(core._is_user_banned({"is_banned": 1, "ban_reason": "限时", "ban_expire_at": future}))
    banned, msg = res
    assert banned is True
    assert "限时" in msg
