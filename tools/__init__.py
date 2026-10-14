"""服务端工具框架（server-side tools）。

APIProxy 作为 LLM 网关，除了透传上游模型能力，也在网关侧提供「服务端工具」：
由网关在把请求转发给上游之前自行执行（如 WebSearch 联网检索），把结果以
system 上下文形式注入，再剥离该工具后转发上游。这样无论上游是否原生支持
web_search，都能得到带实时信息的回答，且对调用方保持 OpenAI 兼容语义。

模块职责：
- base:        Tool / ToolResult 抽象
- websearch:   WebSearchTool（默认 DuckDuckGo HTML，无需密钥；可切 SerpAPI / Brave）
- grounding:   ground_server_tools() —— 请求入口，检测并接地服务端工具
"""
from .base import Tool, ToolResult
from .websearch import WebSearchTool
from .grounding import ground_server_tools, SERVER_TOOL_TYPES

__all__ = [
    "Tool",
    "ToolResult",
    "WebSearchTool",
    "ground_server_tools",
    "SERVER_TOOL_TYPES",
]
