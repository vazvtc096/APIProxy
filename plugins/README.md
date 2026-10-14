# plugins —— 插件目录

把插件放进这个目录就会被自动加载。插件有两种等价形态，管理器自动识别，
代码完全不用改：

```
plugins/DemoPlugin/        目录形态：开发态，改完重启即生效
plugins/DemoPlugin.zip     压缩包形态：分发态，丢进来就能用
```

以下划线或点开头的条目（`.disabled/`、`_tmp/`）会被忽略，可以作为临时下线手段。

## 包内结构

```
DemoPlugin/
  main.py            必需。入口模块，里面定义一个 Plugin 子类
  plugin.json        可选。清单：名称/版本/作者/许可证/标签/兼容声明/配置默认值
  README.md          可选。说明；没写 description 时自动取其首段作为简介
  LICENSE.md         可选。许可证全文；自动识别常见协议名
  requirements.txt   可选。依赖提示（不会自动安装）
  helper.py          可选。插件自己的模块，用 `from .helper import x` 引入
  assets/            可选。任意资源，代码示例见下
```

打包成可分发的 zip（反过来用 `--extract` 解包）：

```bash
python -m plugin.core.pack plugins/DemoPlugin          # → plugins/DemoPlugin.zip
python -m plugin.core.pack plugins/DemoPlugin.zip --extract plugins/
```

zip 内是否多套一层同名目录都支持，不用手工调整。

## 最小插件

```python
# plugins/hello/main.py
from plugin.sync.system import SyncPlugin
from plugin.sync.pages import Wrappers, add_page

class Hello(SyncPlugin):
    name = "hello"
    version = "1.0.0"

    def on_load(self):
        self._h = add_page("/hello", lambda: Wrappers.text("hi"))
```

把 `SyncPlugin` 换成 `AsyncPlugin`、加上 `await` 就是异步版，其余不变。

## 清单字段（plugin.json）

| 字段 | 说明 |
| --- | --- |
| `name` | 显示名，缺省取目录/zip 名 |
| `version` | 版本号，缺省 `0.0.0` |
| `description` | 简介，缺省取 README 首段 |
| `author` / `homepage` | 作者与主页 |
| `license` | 许可证名，缺省从 LICENSE 正文自动识别 |
| `tags` | 标签数组 |
| `requirements` | 依赖提示数组（缺省读 requirements.txt） |
| `min_api` | 要求的插件 API 版本下限 |
| `python` | 要求的 Python 版本，如 `>=3.9` |
| `config` | 配置默认值，管理员在根目录 plugins.json 里的值会覆盖它 |

字段优先级：**清单 > 类的类属性 > README/LICENSE 推断**。

## 启用与配置（根目录 plugins.json）

```json
{
  "enabled": ["pluginlist"],
  "pluginlist": { "for_anyone": true },
  "echouser": { "enabled": false }
}
```

- `enabled` 白名单：写了就只有名单内的插件会加载
- 每个插件块里的 `enabled: false` 可单独关掉该插件
- 其余键是插件自己声明的配置项

## 热重载（改完自动生效）

默认**关闭**（生产不该开）。开启方式二选一：

```bash
PLUGIN_HOT_RELOAD=1                 # 环境变量
PLUGIN_HOT_RELOAD_INTERVAL=0.8      # 巡检间隔，默认 1.0 秒
```

```json
{ "hot_reload": true, "hot_reload_interval": 0.8 }
```

开启后服务会起一条后台巡检线程，盯着 `plugins/` 与 `plugins.json`：

- 改了插件文件 → 只重载这一个插件（卸载 → 清模块缓存 → 重新 import）
- 新增目录 / 丢进新 zip → 自动加载
- 删除 → 自动卸载，路由立刻 404
- 改了 `plugins.json` → 重新读取，新启用的加载、被禁用的卸载
- **新代码有错误时回滚到上一版**，插件不会因为一次语法错误就消失

实现要点：变更一律投递到 app 的事件循环里执行（不在别的线程改 url_map）；
编辑器保存产生的中间态用静默期（默认 0.6s）合并成一次重载。

手动触发（测试或管理接口）：

```python
from plugin import get_hot_reloader
get_hot_reloader().trigger()      # 立刻检查一次，返回本次执行的动作
```

## 运行时 API

- `manager.load_path(path)` / `manager.install(zip_path)` —— 运行时加载或安装插件
- `manager.reload(name)` / `manager.unload(name)` —— 重载或卸载
- `manager.list_available()` —— 列出目录里所有包及其启用/加载状态
- `manager.read_resource(name, member)` —— 读取某个插件包内的资源
- `manager.reload(name)` —— 手动重载（失败自动回滚到上一版源码）
- `get_hot_reloader().trigger()` / `.start(app)` / `.stop()` —— 热重载控制

Demo 写法见本目录下的 `pluginlist`（同步）与 `echouser`（异步）。
