"""plugin.aio.pages —— 异步插件的页面 / 接口注册与响应工具。

典型用法（注意 add_page 与 Wrappers 都支持 await）：
    async def on_load(self):
        self._page_handle = await add_page("/echouser", self.handle_req)

    async def handle_req(self, usrinfo):
        return await Wrappers.jsonify(usrinfo.to_dict())

静态资源同样支持双模：``await serve_assets("/demo", "assets")``。
"""
from ..core.api_impl import add_page, serve_assets, Wrappers, PageHandle

__all__ = ["add_page", "serve_assets", "Wrappers", "PageHandle"]
