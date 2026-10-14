"""工具抽象基类。

Tool 是服务端工具的统一接口：每个工具有 name / description / parameters(JSON Schema)
以及协程 run()。grounding 层据此发现并执行工具。
"""


class ToolResult:
    """工具执行结果。

    content:   已格式化为自然语言的结果文本，可直接注入大模型上下文。
    structured: 结构化结果（如检索到的条目列表），供计费/日志/调试使用。
    """

    def __init__(self, content: str, structured=None):
        self.content = content
        self.structured = structured

    def __repr__(self):
        return f"<ToolResult len={len(self.content)}>"


class Tool:
    # 子类覆盖以下类属性
    name: str = ""
    description: str = ""
    parameters: dict = {}  # JSON Schema

    async def run(self, **kwargs) -> ToolResult:
        raise NotImplementedError
