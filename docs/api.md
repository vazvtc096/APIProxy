# API 文档

> Cloud LLM API 代理服务，完全兼容 OpenAI 格式的 API 接口，支持流式响应。可直接将 openai 官方 SDK 或任意 OpenAI 兼容客户端的 `base_url` 指向本服务。

## 认证方式

所有 API 请求都需要在请求头中携带 API Key：

```
Authorization: Bearer sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

API Key 在仪表板（dashboard）中创建和管理，每个用户最多可创建 10 个。出于安全考虑，账号管理类接口不在本文档公开，请在仪表板界面操作。

> 注意：请妥善保管你的 API Key，不要泄露给他人。如果怀疑 API Key 泄露，请立即在仪表板中删除并重新生成。

## 基础 URL

所有 API 端点都基于以下 URL：

```
{{BASE_URL}}
```

## 聊天补全

### POST /v1/chat/completions

创建聊天补全请求，完全兼容 OpenAI 格式。支持流式和非流式响应。

> 别名：`POST /api/chat/completions` 与本接口等价，`/v1/` 为推荐的标准路径。

#### 请求体

```
{
  "model": "your-model-id",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"}
  ],
  "stream": false,
  "temperature": 0.7,
  "max_tokens": 2000
}
```

#### 参数说明

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `model` | string | 是 | 模型名称，通过 `GET /v1/models` 获取当前上游支持的模型列表 |
| `messages` | array | 是 | 消息列表，每条消息包含 role 和 content |
| `stream` | boolean | 否 | 是否流式响应，默认 false |
| `temperature` | number | 否 | 采样温度，0-2 之间，默认 0.7 |
| `max_tokens` | integer | 否 | 最大生成 token 数 |
| 其他 | - | 否 | `top_p`、`presence_penalty` 等标准 OpenAI 参数将透传给上游 |

#### 响应示例（非流式）

```
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "your-model-id",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello! How can I help you today?"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 20,
    "completion_tokens": 10,
    "total_tokens": 30
  }
}
```

#### 流式响应

当 `stream: true` 时，返回 Server-Sent Events (SSE) 格式的流式响应：

```
data: {"choices":[{"delta":{"content":"Hello"}}]}

data: {"choices":[{"delta":{"content":"!"}}]}

data: [DONE]
```

> 上游长时间无输出时，服务端会发送 SSE 注释心跳 `: ping`，以防止中间代理（如 nginx 60s 读超时）断开连接。出错时会发送 `data: {"error": "..."}`。

## 模型列表

### GET /v1/models

获取当前可用的模型目录，返回 OpenAI 兼容格式。

> 别名：`GET /api/models` 与本接口等价。结果在服务端缓存一小段时间，上游模型目录变化后可能有短暂延迟。

#### 响应示例

```
{
  "object": "list",
  "data": [
    {"id": "gpt-4o-mini"},
    {"id": "gpt-4o"}
  ],
  "count": 2
}
```

模型列表由后台自动从上游拉取，**不再写死**。各模型的单价（每百万 tokens 的输入 / 输出价格）由管理员在 dashboard「模型价格」页动态配置；未配置的模型计费时走兜底价。

> 本服务是通用的 Cloud LLM API 代理，具体可用模型取决于上游供应商的配置。

## Responses API

### POST /v1/responses

OpenAI Responses API 兼容接口。服务端将 `input` 翻译为 chat messages 调用上游，再把结果翻译回 Responses 形状，支持流式 SSE。

#### 请求体

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `model` | string | 是 | 模型名称 |
| `input` | string \| array | 是 | 字符串，或消息项数组 |
| `instructions` | string | 否 | 系统指令，会作为 system 消息前置 |
| `stream` | boolean | 否 | 是否流式响应，默认 false |

#### 请求示例

```
{
  "model": "your-model-id",
  "input": "Hello!"
}
```

#### 响应示例（非流式）

```
{
  "id": "resp_xxxxx",
  "object": "response",
  "created_at": 1700000000,
  "status": "completed",
  "model": "your-model-id",
  "output": [
    {
      "id": "msg_xxxxx",
      "type": "message",
      "status": "completed",
      "role": "assistant",
      "content": [
        {"type": "output_text", "text": "Hello! How can I help?", "annotations": []}
      ]
    }
  ],
  "usage": {"input_tokens": 2, "output_tokens": 8, "total_tokens": 10},
  "incomplete_details": null
}
```

## 错误处理

API 错误响应格式：

```
{
  "error": "错误描述"
}
```

### 常见错误码

| 状态码 | 说明 |
| --- | --- |
| `400` | 请求参数错误，或业务错误（如余额不足） |
| `401` | 未授权（API Key 无效或未登录） |
| `403` | 账号被封禁，或 OAuth token 缺少所需权限 |
| `404` | 资源不存在 |
| `429` | 请求过于频繁，触发限流 |
| `500` | 服务器内部错误（详细信息已记入日志） |
