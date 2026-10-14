"""plugin.async.argument —— 请求级依赖注入（NeedArgument）。

用法与 plugin.sync.argument 完全一致，内部是同一套解析器。
"""
from ..core.api_impl import NeedArgument, resolve_arg

__all__ = ["NeedArgument", "resolve_arg"]
