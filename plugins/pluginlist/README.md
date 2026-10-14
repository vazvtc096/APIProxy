# pluginlist

列出所有已加载插件的元信息。这是插件系统的**同步**示例插件。

## 它演示了什么

| 能力 | 在本插件中的用法 |
| --- | --- |
| 同步生命周期 | 继承 `SyncPlugin`，`on_load` / `handle_req` 都是普通 `def` |
| 配置声明 | `PLConfig.for_anyone: bool = ConfigMethod.AskAdmin`，必须由管理员提供 |
| 依赖注入 | `add_page(..., (NeedArgument.user_info,))` 自动注入当前用户信息 |
| 序列化 | `Wrappers.jsonify(plugins)` 直接序列化全局注册表（对象自带 `to_dict`） |
| 包内资源 | `serve_assets("/pluginlist-assets", "assets")` 把包内目录挂成静态路由 |

## 路由

- `GET /pluginlist` —— 返回插件列表；未登录且未开启 `for_anyone` 时返回空数组
- `GET /pluginlist-assets/<文件名>` —— 返回本插件 `assets/` 下的静态文件

## 配置

`for_anyone` 是 `AskAdmin` 类型，管理员必须显式提供。在根目录的 `plugins.json` 中：

```json
{
  "pluginlist": { "for_anyone": true }
}
```

也可以走环境变量：`PLUGIN_PLUGINLIST_FOR_ANYONE=1`。

## 目录形态与 zip 形态

当前是目录形态。打包成可分发的压缩包：

```bash
python -m plugin.core.pack plugins/pluginlist
```

生成的 `plugins/pluginlist.zip` 可以直接删掉目录单独使用，行为完全一致。
