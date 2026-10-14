"""服务端工具接地（server-side tool grounding）。

请求若携带网关可代为执行的「服务端工具」（目前为 web_search 系列），则由网关
先执行检索、把结果拼成 system 上下文注入 messages，再把这些工具从转发给上游的
tools 里剥离（避免上游不认识而 400）。正常不带服务端工具的请求原样返回，零影响。
"""
import logging

from .websearch import WebSearchTool, _format_results

logger = logging.getLogger("apx.tools.grounding")

# 网关自行处理的工具类型集合（含 OpenAI / Anthropic 原生 web search 类型）
SERVER_TOOL_TYPES = {
    "apx_web_search",        # 本网关自定义
    "web_search_preview",    # OpenAI 原生（o 系列）
    "web_search_20250305",  # Anthropic 原生
}


def _detect_server_tools(tools):
    found = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        ttype = t.get("type")
        if ttype in SERVER_TOOL_TYPES:
            found.append(t)
        elif ttype == "function" and (t.get("function") or {}).get("name") == "web_search":
            found.append(t)
    return found


def _derive_query(messages) -> str:
    """从最后一条用户消息推导检索词。"""
    for m in reversed(messages or []):
        if not isinstance(m, dict):
            continue
        if m.get("role") != "user":
            continue
        c = m.get("content")
        if isinstance(c, str) and c.strip():
            return c.strip()
        if isinstance(c, list):
            for p in c:
                if isinstance(p, dict) and p.get("type") == "text" and p.get("text", "").strip():
                    return p["text"].strip()
    return ""


def _tool_query(t: dict) -> str:
    """从单个服务端工具对象里尝试取出显式 query。"""
    fn = t.get("function") or {}
    q = t.get("query") or fn.get("query")
    if isinstance(q, str) and q.strip():
        return q.strip()
    params = fn.get("parameters")
    if isinstance(params, dict):
        qp = params.get("query")
        if isinstance(qp, str) and qp.strip():
            return qp.strip()
    return ""


async def ground_server_tools(req_data: dict) -> dict:
    """入口：就地（浅拷贝）接地服务端工具，返回（可能修改后的）req_data。

    仅在检测到服务端工具且检索成功时修改 messages / tools；否则原样返回。
    """
    if not isinstance(req_data, dict):
        return req_data
    tools = req_data.get("tools")
    server_tools = _detect_server_tools(tools)
    if not server_tools:
        return req_data

    messages = req_data.get("messages") or []
    num_results = int((tools and tools[0].get("num_results")) or 5)

    queries = []
    for t in server_tools:
        q = _tool_query(t) or _derive_query(messages)
        if q:
            queries.append(q)
    if not queries:
        return req_data

    tool = WebSearchTool()
    contexts = []
    for q in queries[:3]:  # 单次请求最多并联 3 个检索，避免外部调用爆炸
        try:
            res = await tool.run(query=q, num_results=num_results)
            if res and res.content:
                contexts.append(res.content)
        except Exception as e:  # pragma: no cover - 检索失败不阻断主请求
            logger.warning("websearch grounding failed for %r: %s", q, e)

    if not contexts:
        return req_data

    system_ctx = ("You have access to the following web search results. "
                  "Use them to inform your answer when relevant. "
                  "Do not mention the search engine itself.\n\n"
                  + "\n\n".join(contexts))
    new_messages = [{"role": "system", "content": system_ctx}] + list(messages)

    # 浅拷贝 req_data，避免污染调用方原始请求对象
    new_req = dict(req_data)
    new_req["messages"] = new_messages
    remaining = [t for t in (tools or []) if t not in server_tools]
    if remaining:
        new_req["tools"] = remaining
    else:
        new_req.pop("tools", None)
    return new_req
