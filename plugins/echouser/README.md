# echouser

回显当前登录用户信息，并提供一个把包内 README 原样返回的接口。这是插件系统的**异步**示例插件。

## 它演示了什么

- 继承 `AsyncPlugin`，`on_load` / 处理函数都是 `async def`
- `await add_page(...)`、`await Wrappers.jsonify(...)` 的异步调用方式
- `self.read_text("README.md")` 读取本插件包内的文件 —— 即便插件是以 zip 形态
  分发、根本没有解压到磁盘，这行也能正常工作

## 路由

- `GET /echouser` —— 返回当前用户信息；未登录返回 `{"guest": true}`
- `GET /echouser/readme` —— 返回本插件的 README.md 原文

## 为什么它是异步插件

Quart 是全异步框架，`AsyncPlugin` 是推荐写法。但核心 API 是双模的，
把一个 `AsyncPlugin` 改成 `SyncPlugin`（去掉所有 `await`、把 `async def`
改回 `def`）同样能跑，两种写法可以混用。
