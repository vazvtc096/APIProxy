"""plugin.sync.argument —— 请求级依赖注入（NeedArgument）。

插件在 add_page 时声明需要的参数，框架按声明顺序解析并注入：

    add_page("/x", self.handler, (NeedArgument.user_info, NeedArgument.request))
    def handler(self, user: UserInfo, req): ...
"""
from ..core.api_impl import NeedArgument, resolve_arg

__all__ = ["NeedArgument", "resolve_arg"]
