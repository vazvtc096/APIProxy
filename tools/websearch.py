"""WebSearch 工具实现。

后端（环境变量 WEBSEARCH_BACKEND 选择，默认 duckduckgo）：
- duckduckgo：抓取 html.duckduckgo.com 的 HTML 结果页，无需任何密钥，开箱即用。
- serpapi：    SerpAPI（https://serpapi.com），需 WEBSEARCH_API_KEY。
- brave：      Brave Search API（https://brave.com/search/api/），需 WEBSEARCH_API_KEY。

所有网络请求走标准库 urllib + asyncio.to_thread，不引入额外依赖。
"""
import asyncio
import html
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from .base import Tool, ToolResult

logger = logging.getLogger("apx.tools.websearch")

_DDG_HTML = "https://html.duckduckgo.com/html/"
_UA = "Mozilla/5.0 (compatible; APIProxyWebSearch/1.0)"
_TIMEOUT = float(os.environ.get("WEBSEARCH_TIMEOUT", "10"))


def _http_get(url: str, headers=None, timeout: float = None) -> str:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout or _TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace")


def _strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


# ---- DuckDuckGo HTML 解析 ----
_LINK_RE = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_SNIP_RE = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.S)


def _parse_ddg(html_text: str, num: int) -> list:
    links = _LINK_RE.findall(html_text)
    snips = _SNIP_RE.findall(html_text)
    out = []
    for i, (href, title) in enumerate(links[:num]):
        m = re.search(r"uddg=([^&]+)", href)
        url = urllib.parse.unquote(m.group(1)) if m else href
        snippet = _strip_tags(snips[i]) if i < len(snips) else ""
        out.append({"title": _strip_tags(title), "url": url, "snippet": snippet})
    return out


def _format_results(query: str, results: list) -> str:
    if not results:
        return f"[Web search for {query!r} returned no results.]"
    lines = [f"Web search results for {query!r}:", ""]
    for i, r in enumerate(results, 1):
        title = r.get("title") or "(no title)"
        url = r.get("url") or ""
        snip = (r.get("snippet") or "").strip()
        lines.append(f"[{i}] {title}")
        if url:
            lines.append(f"URL: {url}")
        if snip:
            lines.append(snip)
        lines.append("")
    return "\n".join(lines).strip()


async def _search_ddg(query: str, num: int) -> list:
    url = _DDG_HTML + "?" + urllib.parse.urlencode({"q": query})
    try:
        txt = await asyncio.to_thread(_http_get, url)
    except (urllib.error.URLError, OSError) as e:  # pragma: no cover - 网络依赖
        logger.warning("websearch duckduckgo failed: %s", e)
        return []
    return _parse_ddg(txt, num)


async def _search_serpapi(query: str, num: int) -> list:
    key = os.environ.get("WEBSEARCH_API_KEY")
    if not key:
        logger.warning("websearch serpapi requested but WEBSEARCH_API_KEY missing")
        return []
    url = "https://serpapi.com/search.json?" + urllib.parse.urlencode(
        {"q": query, "num": num, "engine": "google", "api_key": key})
    try:
        raw = await asyncio.to_thread(_http_get, url)
        data = json.loads(raw)
    except Exception as e:  # pragma: no cover - 网络/密钥依赖
        logger.warning("websearch serpapi failed: %s", e)
        return []
    out = []
    for r in (data.get("organic_results") or [])[:num]:
        out.append({"title": r.get("title", ""), "url": r.get("link", ""),
                    "snippet": r.get("snippet", "")})
    return out


async def _search_brave(query: str, num: int) -> list:
    key = os.environ.get("WEBSEARCH_API_KEY")
    if not key:
        logger.warning("websearch brave requested but WEBSEARCH_API_KEY missing")
        return []
    url = "https://api.search.brave.com/res/v1/web/search?" + urllib.parse.urlencode(
        {"q": query, "count": num})
    headers = {"User-Agent": _UA,
               "Accept": "application/json",
               "X-Subscription-Token": key}
    try:
        raw = await asyncio.to_thread(_http_get, url, headers, _TIMEOUT)
        data = json.loads(raw)
    except Exception as e:  # pragma: no cover - 网络/密钥依赖
        logger.warning("websearch brave failed: %s", e)
        return []
    out = []
    for r in (data.get("web", {}).get("results") or [])[:num]:
        out.append({"title": r.get("title", ""), "url": r.get("url", ""),
                    "snippet": r.get("description", "")})
    return out


_BACKENDS = {
    "duckduckgo": _search_ddg,
    "serpapi": _search_serpapi,
    "brave": _search_brave,
}


class WebSearchTool(Tool):
    name = "web_search"
    description = ("Search the web for up-to-date information. Returns a list of "
                  "results (title / url / snippet) formatted for LLM context.")
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "The search query."},
            "num_results": {"type": "integer",
                            "description": "Number of results to return.",
                            "default": 5},
        },
        "required": ["query"],
    }

    async def run(self, query: str, num_results: int = 5) -> ToolResult:
        backend = (os.environ.get("WEBSEARCH_BACKEND") or "duckduckgo").lower()
        search = _BACKENDS.get(backend, _search_ddg)
        num = max(1, min(int(num_results or 5), 10))
        results = await search(query, num)
        return ToolResult(content=_format_results(query, results), structured=results)
