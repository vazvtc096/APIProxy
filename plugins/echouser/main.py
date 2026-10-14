"""echouser —— 回显当前登录用户信息（异步插件示例）。

演示：
  - 继承 AsyncPlugin，生命周期与处理函数均为 async def
  - add_page / Wrappers.jsonify 全部以 await 方式调用
  - 用 self.read_text() 读取本插件包内的 README（zip 形态下同样可行）

如果把 AsyncPlugin 换成 SyncPlugin、去掉所有 await，这个插件依旧能正常工作，
这就是 dual() 双模函数的意义所在。
"""
from plugin.aio.system import AsyncPlugin, logger
from plugin.aio.pages import Wrappers, add_page
from plugin.aio.argument import NeedArgument
from plugin.aio.user import UserInfo
from plugin.aio.info import PluginType


class EchoUser(AsyncPlugin):
    name = "echouser"
    version = "1.1.0"
    description = "回显当前登录用户信息"
    plugin_type = PluginType.WEB

    def __init__(self, config=None):
        super().__init__(config)
        self._page_handle = None
        self._readme_handle = None

    async def on_load(self):
        # 异步语境：add_page 返回协程，需要 await
        self._page_handle = await add_page(
            "/echouser", self.handle_req, (NeedArgument.user_info,))
        self._readme_handle = await add_page("/echouser/readme", self.readme_page)
        logger.info("echouser 已加载")

    async def handle_req(self, usrinfo: UserInfo):
        if usrinfo.is_authenticated:
            return await Wrappers.jsonify(usrinfo.to_dict())
        return await Wrappers.jsonify({"guest": True})

    async def readme_page(self):
        """直接把包内的 README.md 原样返回（演示包内资源读取）。"""
        try:
            return Wrappers.text(self.read_text("README.md"))
        except FileNotFoundError:
            return Wrappers.text("README.md not found", status=404)

    async def on_unload(self):
        for handle in (self._page_handle, self._readme_handle):
            if handle:
                handle.close()
        logger.info("echouser 已卸载")
