"""WebSearch 工具框架纯单元测试（无网络 / 无 app 依赖）。

覆盖：DuckDuckGo HTML 解析、服务端工具接地（注入 system 上下文 + 剥离原工具）、
无服务端工具时原样返回、检索为空时不破坏请求。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.grounding import ground_server_tools  # noqa: E402
from tools.base import ToolResult  # noqa: E402

_DDG_FIXTURE = """
<html><body>
<div class="result">
  <a class="result__a" href="/l/?uddg=https%3A%2F%2Fexample.com&amp;abc=1">Example Domain</a>
  <a class="result__snippet" href="/l/?uddg=https%3A%2F%2Fexample.com">Example snippet text here.</a>
</div>
<div class="result">
  <a class="result__a" href="/l/?uddg=https%3A%2F%2Ftest.org">Test Org</a>
  <a class="result__snippet" href="/l/?uddg=https%3A%2F%2Ftest.org">Another snippet.</a>
</div>
</body></html>
"""


def test_parse_ddg():
    from tools.websearch import _parse_ddg
    results = _parse_ddg(_DDG_FIXTURE, 5)
    assert len(results) == 2
    assert results[0]["title"] == "Example Domain"
    assert results[0]["url"] == "https://example.com"
    assert "Example snippet" in results[0]["snippet"]
    assert results[1]["url"] == "https://test.org"


class _FakeWS:
    async def run(self, query, num_results=5):
        return ToolResult(content=f"SEARCH[{query}] result text", structured=[])


class _FakeEmpty:
    async def run(self, query, num_results=5):
        return ToolResult(content="", structured=[])


def test_ground_injects_and_strips(monkeypatch):
    import tools.grounding as g
    monkeypatch.setattr(g, "WebSearchTool", _FakeWS)
    req = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "latest news?"}],
        "tools": [{"type": "apx_web_search", "num_results": 3}],
    }
    out = asyncio.run(ground_server_tools(req))
    assert out["messages"][0]["role"] == "system"
    assert "SEARCH[latest news?]" in out["messages"][0]["content"]
    assert out["messages"][1]["role"] == "user"
    assert "tools" not in out  # 服务端工具已剥离


def test_ground_openai_native_type(monkeypatch):
    import tools.grounding as g
    monkeypatch.setattr(g, "WebSearchTool", _FakeWS)
    req = {
        "messages": [{"role": "user", "content": "weather today"}],
        "tools": [{"type": "web_search_preview"}],
    }
    out = asyncio.run(ground_server_tools(req))
    assert "SEARCH[weather today]" in out["messages"][0]["content"]
    assert "tools" not in out


def test_ground_noop_without_server_tools():
    req = {"model": "x", "messages": [{"role": "user", "content": "hi"}],
           "tools": [{"type": "function", "function": {"name": "foo"}}]}
    out = asyncio.run(ground_server_tools(req))
    assert out is req  # 原样返回同一对象


def test_ground_empty_search_noop(monkeypatch):
    import tools.grounding as g
    monkeypatch.setattr(g, "WebSearchTool", _FakeEmpty)
    req = {"model": "x", "messages": [{"role": "user", "content": "q"}],
           "tools": [{"type": "apx_web_search"}]}
    out = asyncio.run(ground_server_tools(req))
    assert out == req  # 检索失败不破坏原请求
