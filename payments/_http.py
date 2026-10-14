# -*- coding: utf-8 -*-
"""极简异步 HTTP 助手（stdlib urllib + asyncio.to_thread）。

不引入新依赖（requests/httpx），与项目既有网络层写法一致。
所有函数返回 (status_code:int, parsed) —— parsed 为 JSON dict 或原始文本 str；
网络层异常返回 (0, "<error>")。
"""
from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_UA = "APIProxy-Payments/1.0"


def _sync_request(method, url, data=None, headers=None, timeout=15.0):
    req = urllib.request.Request(
        url, data=data, headers=dict(headers or {}), method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, (e.read() or b"")
        except Exception:
            return e.code, b""
    except Exception as e:  # noqa: BLE001 - 网络异常统一降级
        return 0, str(e).encode("utf-8")


def _maybe_json(raw: bytes):
    if raw is None:
        return ""
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        try:
            return raw.decode("utf-8")
        except Exception:
            return ""


async def request(method, url, data=None, headers=None, timeout=15.0):
    return await asyncio.to_thread(_sync_request, method, url, data, headers, timeout)


async def get_json(url, headers=None, timeout=15.0):
    h = {"User-Agent": DEFAULT_UA, **(headers or {})}
    code, raw = await request("GET", url, None, h, timeout)
    return code, _maybe_json(raw)


async def post_json(url, obj, headers=None, timeout=15.0):
    h = {"Content-Type": "application/json", "User-Agent": DEFAULT_UA, **(headers or {})}
    code, raw = await request("POST", url, json.dumps(obj).encode("utf-8"), h, timeout)
    return code, _maybe_json(raw)


async def post_form(url, obj, headers=None, timeout=15.0):
    h = {"Content-Type": "application/x-www-form-urlencoded",
         "User-Agent": DEFAULT_UA, **(headers or {})}
    code, raw = await request("POST", url, urllib.parse.urlencode(obj).encode("utf-8"), h, timeout)
    return code, _maybe_json(raw)


async def post_raw(url, body: bytes, headers=None, timeout=15.0):
    h = {"User-Agent": DEFAULT_UA, **(headers or {})}
    code, raw = await request("POST", url, body if isinstance(body, bytes) else str(body).encode("utf-8"), h, timeout)
    return code, _maybe_json(raw)
