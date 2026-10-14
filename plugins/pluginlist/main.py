"""pluginlist —— 列出所有已加载插件（同步插件示例）。

演示：
  - 继承 SyncPlugin，生命周期与处理函数均为普通 def
  - 用 Config + ConfigMethod.AskAdmin 声明需要管理员提供的配置项
  - 用 NeedArgument.user_info 注入当前用户信息
  - 用 Wrappers.jsonify 直接序列化全局插件注册表（对象提供 to_dict）
  - 用 serve_assets 把包内 assets/ 挂成静态路由（zip 形态下同样可用）

磁盘上的完整形态：main.py + plugin.json + README.md + LICENSE.md + assets/
"""
from plugin.sync.system import SyncPlugin, logger
from plugin.sync.pages import Wrappers, add_page, serve_assets
from plugin.sync.argument import NeedArgument
from plugin.sync.user import UserInfo
from plugin.sync.config import Config, ConfigMethod
from plugin.sync.info import PluginType, plugins


class PLConfig(Config):
    """插件配置：for_anyone 需由管理员在 plugins.json 中提供。"""
    for_anyone: bool = ConfigMethod.AskAdmin


class PluginList(SyncPlugin):
    name = "pluginlist"
    version = "1.1.0"
    description = "列出已加载插件的元信息"
    plugin_type = PluginType.SYSTEM
    Config = PLConfig

    def __init__(self, config=None):
        super().__init__(config)
        self.for_anyone = bool(config.for_anyone) if config else False
        self._page_handle = None
        self._asset_handle = None

    def on_load(self):
        # 同步语境：add_page 直接返回 PageHandle，无需 await
        self._page_handle = add_page(
            "/pluginlist", self.handle_req, (NeedArgument.user_info,))
        # 把包内 assets/ 目录挂到 /pluginlist-assets/<文件名>
        self._asset_handle = serve_assets("/pluginlist-assets", "assets")
        logger.info("pluginlist 已加载（for_anyone=%s）", self.for_anyone)

    def handle_req(self, usrinfo: UserInfo):
        if self.for_anyone or usrinfo.is_admin:
            return Wrappers.jsonify(plugins)
        return Wrappers.jsonify([])

    def on_unload(self):
        for handle in (self._page_handle, self._asset_handle):
            if handle:
                handle.close()
        logger.info("pluginlist 已卸载")
