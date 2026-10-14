"""plugin.sync.pages —— 同步插件的页面 / 接口注册与响应工具。

典型用法：
    handle = add_page("/pluginlist", self.handle_req, (NeedArgument.user_info,))
    return Wrappers.jsonify(plugins)     # 同步语境直接返回结果
    return await Wrappers.jsonify(...)   # 异步语境也可以 await

静态资源（从插件包里读，zip 形态无需解压）：
    handle = serve_assets("/demo", "assets")
"""
from ..core.api_impl import add_page, serve_assets, Wrappers, PageHandle

__all__ = ["add_page", "serve_assets", "Wrappers", "PageHandle"]
