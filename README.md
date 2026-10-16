# APIProxy

一个 **OpenAI 兼容的 LLM API 代理服务**，基于 [Quart](https://quart.palletsprojects.com/)（异步 Web 框架）构建。将多个上游大模型 API Key 聚合为一个统一入口，提供按字符计价计费、用户与 API Key 体系、WAF、限流、集群、Debug Console 远程控制台、OAuth 2.0 授权服务器、社交与调度等完整的企业级能力。

---

## 目录

- [核心特性](#核心特性)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [目录结构](#目录结构)
- [功能详解](#功能详解)
- [API 端点概览](#api-端点概览)
- [测试](#测试)
- [部署](#部署)
- [监控](#监控)

---

## 核心特性

| 类别 | 能力 |
|---|---|
| **代理** | OpenAI 兼容的 `/v1/chat/completions`、`/v1/responses`、`/v1/models`，流式与非流式 |
| **多上游** | 按优先级、启用状态、禁用模型自动挑选上游 Key |
| **计费** | 按字符估算 token 计价，支持时段价、上游专属价（`model@upstream`）、原子扣费防并发超支 |
| **用户体系** | 注册/登录、余额、充值审批、封禁/解封、多设备会话限制 |
| **API Key** | 独立 API Key 生成、吊销、余额绑定 |
| **安全** | WAF（SQLi/XSS/路径遍历/扫描器/恶意 UA）、CSRF 双校验、CSP nonce、设备指纹、审计表、限流 |
| **OAuth 2.0** | 授权码 + PKCE、客户端凭证、设备授权流、刷新令牌、吊销（RFC 7009）、内省（RFC 7662） |
| **Debug Console** | TCP 远程控制台 + Web 双重认证，25 个管理命令 |
| **集群** | 多 Worker + LB，PostgreSQL 强一致并发（`FOR UPDATE SKIP LOCKED`） |
| **社交** | 帖子、好友、聊天、转账、红包 |
| **可观测** | `/metrics`（Prometheus）、`/health`、`/ready`、结构化日志 |

---

## 技术栈

| 组件 | 用途 |
|---|---|
| Quart + hypercorn | 异步 Web 框架与 ASGI 服务器 |
| openai | 上游 LLM 客户端 |
| SQLite / PostgreSQL | 数据库双后端（PostgreSQL 支持集群强一致） |
| Redis | 可选：限流、会话缓存 |
| PyJWT | OAuth access token 签名（HS256） |
| bcrypt | 密码哈希 |
| prometheus-client | 指标暴露 |
| alembic + SQLAlchemy | 数据库迁移与 ORM |
| PyYAML | 配置解析 |

完整依赖见 [`requirements.txt`](requirements.txt)。

---

## 快速开始

### 1. 安装

```bash
pip install -r requirements.txt
```

### 2. 配置

两种方式任选其一，**都可以在没有 `config.yaml` 的情况下启动**：

```bash
cp .env.example .env                  # 方式 A：环境变量（容器 / 生产推荐）
cp config.yaml.example config.yaml    # 方式 B：配置文件（本地开发方便）
```

最小配置示例（`config.yaml`）：

```yaml
upstreams:
  - name: "deepseek-main"
    base_url: "https://api.deepseek.com/v1"
    api_key: ""              # 或环境变量 APIPROXY_UPSTREAM_DEEPSEEK_MAIN_API_KEY
    priority: 1
    enabled: true
    disabled_models: []

OAUTH_JWT_SECRET: ""         # 生产必须设置，否则 OAuth fail-closed 拒绝启动
```

> - 所有顶层标量键都可用环境变量 `APIPROXY_<大写键名>` 覆盖（如 `APIPROXY_OAUTH_JWT_SECRET`）。
>   环境变量**可以引入配置文件中不存在的键**，所以纯环境变量部署（不放 `config.yaml`）同样可启动。
> - 同目录下的 `.env` 会被自动加载（真实环境变量优先于 `.env`）。
> - 敏感密钥建议从环境变量注入，不要写进配置文件。

### 3. 启动

```bash
python -m APIProxy
```

默认监听 `0.0.0.0:5000`（HTTP）。启用 HTTPS 时（`SSL_ENABLED: true`）由 hypercorn 承载 TLS 1.2/1.3。

首次启动会自动：初始化数据库 schema（Alembic 迁移，失败回退幂等建表）、生成自签名证书（如启用 HTTPS）、生成 Debug Console 密钥。

### 4. 验证

```bash
curl http://localhost:5000/health
curl http://localhost:5000/metrics
```

---

## 配置说明

配置文件支持 `config.toml > config.yaml > config.yml > config.json` 优先级。关键配置项：

| 键 | 默认 | 说明 |
|---|---|---|
| `upstreams` | — | 多上游列表（name/base_url/api_key/priority/enabled/disabled_models） |
| `DB_TYPE` | `sqlite` | `sqlite` 或 `postgres` |
| `DATABASE_URL` | — | PostgreSQL 连接串（`DB_TYPE: postgres` 时必填） |
| `SSL_ENABLED` | `false` | 是否启用 HTTPS |
| `DEBUG_CONSOLE_ENABLED` | `true` | 是否启用 Debug Console 远程控制台 |
| `WAF_ENABLED` | `true` | 是否启用 WAF |
| `WAF_ALLOWED_HOSTS` | 空 | 逗号分隔的合法 Host，空则不校验 |
| `WAF_GLOBAL_RPM` | 180 | 每 IP 每分钟请求上限 |
| `CLOUDFLARE_TRUSTED` | `auto` | 是否信任 Cloudflare 转发的真实 IP |
| `pricing` | — | 模型定价（default / models / schedules / `model@upstream`） |
| `OAUTH_JWT_SECRET` | 空 | OAuth JWT 签名密钥（**生产必填，fail-closed**） |

完整配置项与注释见 [`config.yaml.example`](config.yaml.example)（`config.yaml` 含密钥不入库）。

---

## 目录结构

```
APIProxy/
├── __main__.py            # 入口：create_app、preflight、启动
├── app.py                 # Quart app 实例
├── configs.py             # 配置加载
├── db.py                  # 数据库抽象层（SQLite/PostgreSQL）
├── upstreams.py           # 多上游管理
├── pricing.py             # 定价解析
├── oauth.py               # OAuth 2.0 授权服务器
├── waf.py                 # WAF + 行为监测
├── security.py            # 封禁、设备指纹
├── Debug Console.py / debug_console_server.py / debug_console_crypto.py  # Debug Console 远程控制台
├── scheduler.py           # 定时任务调度器
├── cluster.py             # 集群发现与 LB
├── social.py              # 社交（帖子/好友/聊天/转账）
├── cloudflare.py          # Cloudflare 真实 IP
├── redis_client.py        # Redis 客户端
├── constants.py           # token 计价常量
├── apikey.py              # API Key 管理
├── hooks.py / announcements.py  # 钩子 / 公告
│
├── core/                  # 从 core.py 拆出的职责模块（13 个）
│   ├── core_db.py         # 数据库基础层
│   ├── core_http.py       # 请求上下文
│   ├── core_net_utils.py  # CIDR/URI/scope
│   ├── core_security_utils.py  # HTML 净化、用户名、安全常量
│   ├── core_auth.py       # 权限、封禁检查
│   ├── core_proxy_utils.py  # 上游 payload、chat↔responses
│   ├── core_rate_limit.py # 限流
│   ├── core_billing.py    # 计费、原子扣费
│   ├── core_oauth.py      # OAuth 辅助
│   ├── core_docs.py       # 文档、用量统计
│   ├── core_tasks.py      # UserTaskManager 队列/Worker
│   ├── core_session.py    # 会话管理
│   └── core_debug_console.py       # Debug Console 密钥 + 命令 handler
├── core.py                # 聚合入口：__all__ 重导出 + CSRF + 登录日志
│
├── routes/                # 12 个路由蓝图
│   ├── chat_proxy.py      # OpenAI 兼容代理
│   ├── auth.py / user.py / admin.py / recharge.py
│   ├── social.py / oauth_routes.py / debug_console_routes.py
│   ├── pages.py / email_captcha.py / health.py / cluster_routes.py
│
├── middleware/
│   └── security_middleware.py  # WAF / CSRF / 安全头
├── utils/
│   ├── metrics.py         # Prometheus 指标
│   ├── errors.py / endpoints.py / logging_setup.py
│
├── tests/                 # 148 个测试用例
├── docs/                  # api.md、OAUTH_GUIDE.md
├── migrations/            # Alembic 迁移
├── certs/                 # TLS 证书
├── Dockerfile / docker-compose.yml / nginx_example.conf
├── prometheus_alerts.yml  # Prometheus 告警规则
├── .env.example           # 环境变量模板（cp 为 .env 即自动加载）
└── config.yaml.example    # 配置模板（config.yaml 含密钥不入库）
```

> **架构说明**：`core.py` 原为 2489 行的 God module，已拆分为 13 个职责单一模块，`core.py` 仅保留 `__all__` 重导出（134 个符号）与少量未下沉功能，`from APIProxy import core; core.xxx` 及 `from ..core import *` 完全向后兼容。

---

## 功能详解

### 代理与计费

- 请求进入 `/v1/chat/completions` 或 `/v1/responses` 后，按模型挑选「启用 + 未禁用该模型 + 优先级最高」的上游。
- 每个用户拥有独立队列与 Worker（`UserTaskManager`），串行处理该用户的请求，避免并发超支。
- 计费采用「查表法」按字符估算 token，再乘以每百万 token 单价（由 `pricing` 解析，支持时段价与上游专属价）。
- 扣费为原子操作（`BEGIN IMMEDIATE` 锁定行），先预扣输入费用，输出产生后再强制扣输出费用，失败自动回退。

### 安全

- **WAF**：对 SQL 注入、XSS、路径遍历、漏洞扫描器路径、恶意 UA 做特征匹配；请求体仅在非自由文本端点检查，避免误杀正常 prompt。
- **CSRF**：同步令牌 + Origin/Referer 双校验，配合 CSP nonce。
- **限流**：Redis 优先（原子 INCR + EXPIRE），SQLite 回退（事务写锁）。
- **封禁**：账号封禁（含到期时间）、IP 黑名单、行为违规自动封禁。

### OAuth 2.0

实现 RFC 6749 授权码模式 + PKCE（RFC 7636）、客户端凭证模式、设备授权流（RFC 8628），以及刷新令牌、吊销（RFC 7009）、内省（RFC 7662）、动态客户端注册（RFC 7591）。access token 为 HS256 JWT（无状态校验），refresh token 为不透明随机串并落库。详见 [`docs/OAUTH_GUIDE.md`](docs/OAUTH_GUIDE.md)。

### Debug Console 远程控制台

- TCP 服务（独立端口）+ Web 管理端双重认证。
- 25 个命令：用户管理（增删查、封禁、余额）、充值审批、会话管理、API Key 管理、Debug Console 密钥管理、IP 白名单等。
- 命令分发已拆为 `_Debug Console_cmd_<name>` handler + `_DEBUG_CONSOLE_HANDLERS` 映射表。

### 集群

支持单机、多 Worker + LB 两种模式。启用 PostgreSQL 后，调度器用 `FOR UPDATE SKIP LOCKED` 做跨进程互斥，多 Worker 抢同一任务不会重复执行。

---

## API 端点概览

| 路径 | 说明 |
|---|---|
| `/v1/chat/completions` | OpenAI 兼容聊天补全（流式 + 非流式） |
| `/v1/responses` | OpenAI Responses 兼容端点 |
| `/v1/models`、`/api/models` | 模型列表（合并所有上游，带缓存） |
| `/api/chat/*` | 会话内聊天（社交聊天） |
| `/register`、`/login` | 注册 / 登录 |
| `/api/user/*` | 用户信息、设置、API Key 管理 |
| `/api/admin/*` | 管理端（用户、充值、封禁、白名单） |
| `/api/recharge/*` | 充值请求与审批 |
| `/oauth/*` | OAuth 2.0 授权服务器 |
| `/api/debug-console/*` | Debug Console Web 管理端 |
| `/health`、`/ready` | 存活 / 就绪探针 |
| `/metrics` | Prometheus 指标 |

完整 API 参考见 [`docs/api.md`](docs/api.md)。

---

## 测试

```bash
# 从项目父目录运行（包名 APIProxy 与目录同名，需将父目录加入 PYTHONPATH）
cd .. && PYTHONPATH=. python -m pytest APIProxy/tests/
```

共 **77 个测试用例**，覆盖：

- 计费、封禁、调度频率、内容净化、CIDR/OAuth 纯函数
- WAF 攻击特征正则、OAuth PKCE/JWT
- 端到端集成测试（WAF 中间件拦截、OAuth 端点鉴权）

---

## 部署

### Docker

```bash
docker compose up -d
```

### 生产建议

- 设置 `OAUTH_JWT_SECRET`、`SESSION_SECRET`、`TOKEN_SECRET`（从环境变量注入，勿写入配置）。
- 生产关闭 `DEBUG`（默认已关闭），启用 HTTPS（`SSL_ENABLED: true`）。
- 使用 `WEB_CONCURRENCY` 控制 hypercorn worker 数，`GRACEFUL_TIMEOUT` 控制优雅停机时长。
- 反向代理参考 [`nginx_example.conf`](nginx_example.conf)。
- CI 模板见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)（compileall + pytest + pip-audit）。

---

## 监控

- **`/metrics`**：HTTP 指标（请求数、延迟、在途请求）+ 业务指标（上游延迟、令牌消耗、费用、上游错误）。
- **`/health`**：存活探针（进程 + 数据库连接）。
- **`/ready`**：就绪探针（数据库硬依赖、Redis 软依赖）。
- **告警规则**：见 [`prometheus_alerts.yml`](prometheus_alerts.yml)，覆盖 5xx/4xx 错误率、P95 延迟、请求积压、实例宕机。

---

## 许可

本项目基于 [MIT License](LICENSE) 开源。
