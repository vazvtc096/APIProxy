# API 文档

本服务兼容 OpenAI API 规范，可直接将 openai 官方 SDK 或任意 OpenAI 兼容客户端的 `base_url` 指向本服务使用。

## 目录

- [通用说明](#通用说明)
- [模型列表](#模型列表)
- [聊天补全](#聊天补全)
- [Responses API](#responses-api)

---

## 通用说明

- 基础 URL：`https://your-domain.com`
- 接口返回 JSON；流式接口返回 SSE（`text/event-stream`）
- 认证方式：`Authorization: Bearer <API Key 或 OAuth access token>`
  - OAuth token 需包含 `api` scope
  - API Key 在用户后台创建，本文档不公开其创建接口
- 错误响应格式：`{"error": "错误信息"}`，部分带 `error_description`
- 所有接口均按 token 维度限流，触发限流返回 `429`

---

## 模型列表

获取可用模型目录（OpenAI 兼容）。

**请求**

```
GET /v1/models
Authorization: Bearer <API Key 或 OAuth access token>
```

> 别名：`GET /api/models` 等价。已登录的浏览器会话也可访问。

**响应示例**

```json
{
  "object": "list",
  "data": [
    { "id": "gpt-4o-mini" },
    { "id": "gpt-4o" }
  ],
  "count": 2
}
```

**说明**

- 结果在服务端缓存一小段时间，上游模型目录变化后可能有短暂延迟。
- 返回的模型 id 可直接用于 [聊天补全](#聊天补全) 的 `model` 字段。

---

## 聊天补全

OpenAI Chat Completions 兼容接口。

**请求**

```
POST /v1/chat/completions
Authorization: Bearer <API Key 或 OAuth access token>
Content-Type: application/json
```

> 别名：`POST /api/chat/completions` 等价。

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `model` | string | 是 | 模型 id，见 [模型列表](#模型列表) |
| `messages` | array | 是 | 消息数组，元素形如 `{"role":"user","content":"..."}` |
| `stream` | bool | 否 | `true` 时返回 SSE 流，默认 `false` |
| 其他 | - | 否 | `temperature`、`max_tokens`、`top_p` 等标准参数将透传给上游 |

**请求示例（非流式）**

```json
{
  "model": "gpt-4o-mini",
  "messages": [
    { "role": "system", "content": "你是一个助手" },
    { "role": "user", "content": "你好" }
  ]
}
```

**响应（非流式，200）**

返回标准 OpenAI `chat.completion` 对象，包含 `choices` 与 `usage` 等字段。

**响应（流式，`stream: true`）**

- `Content-Type: text/event-stream`
- 每个数据块：`data: {OpenAI chunk}\n\n`
- 结束标记：`data: [DONE]\n\n`
- 出错时：`data: {"error": "..."}\n\n`
- 上游长时间无输出时，服务端会发送 SSE 注释心跳 `: ping` 以防中间代理（如 nginx 60s 读超时）断开连接

**错误码**

| 状态码 | 含义 |
|--------|------|
| 400 | 请求体非法，或业务错误（如余额不足） |
| 401 | 缺失 / 无效的 Authorization，或 token 无效 |
| 403 | 账号被封禁，或 OAuth token 缺少 `api` scope |
| 429 | 触发限流 |
| 500 | 内部错误（详细信息已脱敏并记入日志） |

---

## Responses API

OpenAI Responses API 兼容接口。服务端将 `input` 翻译为 chat messages 调用上游，再把结果翻译回 Responses 形状，支持流式 SSE。

**请求**

```
POST /v1/responses
Authorization: Bearer <API Key 或 OAuth access token>
Content-Type: application/json
```

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `model` | string | 是 | 模型 id |
| `input` | string \| array | 是 | 字符串，或消息项数组（如 `[{"type":"message","role":"user","content":[{"type":"input_text","text":"你好"}]}]`） |
| `instructions` | string | 否 | 系统指令，会作为 `system` 消息前置 |
| `stream` | bool | 否 | `true` 时返回 SSE 流 |

**请求示例**

```json
{
  "model": "gpt-4o-mini",
  "input": "你好"
}
```

**响应示例（非流式，200）**

```json
{
  "id": "resp_xxxxxxxxxxxx",
  "object": "response",
  "created_at": 1234567890,
  "status": "completed",
  "model": "gpt-4o-mini",
  "output": [
    {
      "id": "msg_xxxxxxxxxxxx",
      "type": "message",
      "status": "completed",
      "role": "assistant",
      "content": [
        { "type": "output_text", "text": "你好！", "annotations": [] }
      ]
    }
  ],
  "usage": {
    "input_tokens": 2,
    "output_tokens": 5,
    "total_tokens": 7
  },
  "incomplete_details": null
}
```

**流式（`stream: true`）**：返回 SSE，事件格式同 OpenAI Responses 流式协议。

**错误码**：同 [聊天补全](#聊天补全)。
