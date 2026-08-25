# OAuth 2.0 接入指南

本代理的 OAuth 2.0 采用 **授权码 + PKCE** 流程（与 GitHub 公共客户端一致）：**无需创建客户端**，使用内置公开客户端 `client_id=default` 即可直接获取 Token。整个流程 Token 不进入 URL 片段，安全性高于隐式流。

## 核心流程（授权码 + PKCE，无客户端）

1. 前端生成 PKCE 参数（`code_verifier` / `code_challenge`），并与 `redirect_uri` 一起暂存到 `sessionStorage`：

```js
function base64url(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function randVerifier(){ const a = new Uint8Array(32); crypto.getRandomValues(a); return base64url(a); }
const verifier = randVerifier();
const challenge = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)).then(base64url);
sessionStorage.setItem('oauth_pkce', JSON.stringify({ verifier, redirect_uri: location.origin + '/oauth/callback' }));
```

2. 跳转授权地址（使用内置 `client_id=default`，`response_type=code`）：

```
{{BASE_URL}}/oauth/authorize?response_type=code&client_id=default&code_challenge=<challenge>&code_challenge_method=S256&redirect_uri={{BASE_URL}}/oauth/callback&scope=api&state=<random>
```

3. 页面跳转到登录页，输入你的用户名与密码登录。
4. 登录后进入**授权确认页**（GitHub 风格），列出本次申请的作用域；点「授权」继续，点「取消」则中止授权、返回 `access_denied`。
5. 确认授权后，浏览器重定向到 `redirect_uri`，授权码附在查询参数：

```
{{BASE_URL}}/oauth/callback?code=xxxxx&state=<random>
```

6. 回调页用 `code` + 暂存的 `code_verifier` 向 `/oauth/token` 换取令牌（本代理内置回调页 `{{BASE_URL}}/oauth/callback` 已自动完成此步，你也可以自建回调页）：

```js
const pkce = JSON.parse(sessionStorage.getItem('oauth_pkce'));
const body = new URLSearchParams({
  grant_type: 'authorization_code',
  code: new URLSearchParams(location.search).get('code'),
  code_verifier: pkce.verifier,
  redirect_uri: pkce.redirect_uri,
  client_id: 'default'
});
const resp = await fetch('{{BASE_URL}}/oauth/token', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body });
const token = await resp.json(); // { access_token, token_type, expires_in, scope, refresh_token }
```

7. 调用代理接口时，在请求头带上该 Token：

```
Authorization: Bearer <access_token>
```

## 参数说明

| 参数 | 说明 |
| --- | --- |
| `response_type` | 固定为 `code`（授权码模式）。 |
| `client_id` | 固定为 `default`（内置公开客户端，无需注册）。 |
| `code_challenge` / `code_challenge_method` | PKCE 必填：`code_challenge` 为 `code_verifier` 的 S256 哈希（base64url），`code_challenge_method=S256`。 |
| `redirect_uri` | 接收授权码的回调地址，必须是 `http(s)` 绝对地址（可为任意外部 / 第三方站点，不强制同源）。第三方应用填自己的接收页即可。 |
| `scope` | 申请的作用域，默认 `api`。多个作用域以空格分隔，如 `api profile`。完整列表见下方「作用域与访问地址」。 |
| `state` | 可选，原样回传，用于防 CSRF。 |

> 注意：`redirect_uri` 支持任意 `http(s)` 外部地址（便于第三方应用接入），但仍需防范开放重定向风险；本模式强制要求 PKCE，防止授权码拦截与令牌泄漏。

## 使用 Token 访问接口

拿到 `access_token` 后，请统一访问 **OAuth 专用命名空间** `{{BASE_URL}}/api/oauth/<资源>`，请求头带：

```
Authorization: Bearer <access_token>
```

这一层是专门为第三方授权访问准备的，与仪表盘自己用的 `/api/*` 分开：

- **只认 Bearer 令牌**，不接受浏览器 cookie 会话，缺少或无效令牌一律 `401 invalid_token`；
- **已开放跨域（CORS）**，任意来源的网页应用都能直接 `fetch` 调用；
- **不下发会话 cookie**，第三方拿到的始终只是那枚 access_token，换不到浏览器会话；
- 用 HTTP 方法区分读写：`GET` = 读（`*:read`）、`POST` = 写（`*:write`）、`DELETE` = 删除；
- scope 不足返回 `403 insufficient_scope`，并在 `error_description` 里列出缺哪几个。

先调 `GET {{BASE_URL}}/api/oauth` 可拿到**资源目录**，其中标注了每个资源所需 scope、以及当前令牌是否已获授权：

```json
{
  "base": "/api/oauth",
  "scope": "profile posts:read ...",
  "resources": {
    "posts": {
      "path": "/api/oauth/posts",
      "methods": {
        "GET":  { "scope": "posts:read",  "granted": true },
        "POST": { "scope": "posts:write", "granted": false }
      }
    }
  }
}
```

## 作用域与访问地址

| 作用域 | 说明 | 访问地址 |
| --- | --- | --- |
| `openid` | 返回用户标识 `sub` | `GET {{BASE_URL}}/api/oauth/userinfo` |
| `profile` | 基本资料（用户名 / UID / 注册时间） | `GET {{BASE_URL}}/api/oauth/userinfo` |
| `email` | 邮箱地址 | `GET {{BASE_URL}}/api/oauth/userinfo` |
| `posts:read` | 读取帖子 | `GET {{BASE_URL}}/api/oauth/posts` |
| `posts:write` | 发布帖子 | `POST {{BASE_URL}}/api/oauth/posts` |
| `friends:read` | 好友列表 | `GET {{BASE_URL}}/api/oauth/friends` |
| `friends:write` | 发送好友请求 | `POST {{BASE_URL}}/api/oauth/friends` |
| `chat:read` | 会话列表 | `GET {{BASE_URL}}/api/oauth/chat` |
| `chat:write` | 发消息 / 转账 / 红包 | `POST {{BASE_URL}}/api/oauth/chat` |
| `transactions:read` | 交易记录与余额 | `GET {{BASE_URL}}/api/oauth/transactions` |
| `transactions:write` | 充值请求 | `POST {{BASE_URL}}/api/oauth/transactions` |
| `apikeys:read` | API Key 列表 | `GET {{BASE_URL}}/api/oauth/apikeys` |
| `apikeys:write` | 创建 / 删除 API Key | `POST {{BASE_URL}}/api/oauth/apikeys`、`DELETE {{BASE_URL}}/api/oauth/apikeys/<key>` |
| `user:read` | 个人设置 | `GET {{BASE_URL}}/api/oauth/settings` |
| `user:write` | 修改个人设置 | `POST {{BASE_URL}}/api/oauth/settings` |
| `api` | 调用 Cloud LLM API 代理（聊天补全 / 模型列表） | `POST {{BASE_URL}}/api/chat/completions`（沿用原地址）；模型列表 `GET {{BASE_URL}}/api/models` |
| `rcon` | 远程控制台（仅管理员） | `POST {{BASE_URL}}/api/rcon`（不授予 `default`） |

内置 `default` 客户端已授予除 `rcon` 外的全部作用域，开箱即用。

> 兼容说明：仪表盘原有地址（`/api/posts`、`/apikeys` 等）同样接受 Bearer 令牌，服务端到服务端调用仍可使用；但它们**不开放跨域**，浏览器里的第三方网页应用请走 `/api/oauth/` 命名空间。

## 说明

- 授权码模式会同时返回 `refresh_token`，可在过期后用刷新接口换取新令牌，无需重新走授权流程。
- 标准授权码流程也支持**已注册客户端**（带 `client_secret` 的 confidential 客户端），用于需要服务端保密的场景；普通接入使用内置 `default` 客户端即可。
- 本指南中的 `{{BASE_URL}}` 会自动替换为你当前访问站点的真实地址，无需手动修改域名。
