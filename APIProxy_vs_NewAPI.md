# APIProxy vs NewAPI 完整对比

> 对比基准：2026-10-13（相对 2026-10-08 初版重对比）
> 数据来源：APIProxy 侧基于 `E:\Code\APIProxy` 真实源码核查（文件:行已标注，含 `git log` 最近 3 次提交）；NewAPI 侧基于其公开 changelog / releases（QuantumNous/new-api，截至 **v1.0.0-rc.42**，2026-10）。
> 说明：APIProxy 现以 **MIT License**（Copyright 2026 vazvtc096）开源；NewAPI 为 **AGPLv3** 开源项目（Go + Gin + Vue）。两项目结论均以各自源码/文档为准。

---

## 0. 一句话定位

- **APIProxy**：把"LLM 网关 + to-C 计费 SaaS + 自有 OAuth 身份提供商 + 社交 + 游戏服控制台(RCON) + 多节点集群 + 安全设备"塞进一个进程，并以 **Python + C 原生加速器 + Java/Node 侧翼** 的多语言架构运行。重心在**面向终端用户的经营与强安全**，现已工程化开源（MIT + Docker）。
- **NewAPI**：聚焦的多厂商 LLM 聚合网关 + AI 资产管理系统（One API 二次开发）。重心在**把几十家上游聚合成一个 OpenAI 兼容入口**，且近期已补齐实验性插件体系。

两者在"网关"层高度重叠，真正的分野是**范围与定位**：APIProxy 是生意本体，NewAPI 是零件（但零件现在也更完整了）。

---

## 1. 顶层架构对比

| 维度 | APIProxy | NewAPI |
|---|---|---|
| 编程语言 | **多语言**：Python（Quart + Hypercorn，async ASGI）+ C 原生加速器（ctypes）+ Java/Node 侧翼 | Go（Gin）+ Vue 前端（单一语言栈） |
| 多语言负担 | 是：Java 12540 行 Spring Boot 侧翼 + C 401 行原生加速器（编译为 `_apx_native.dll`）+ Node sidecar | 否，单一 Go 仓库 |
| 许可证 | **MIT**（宽松，派生可闭源商用，须保留版权声明） | **AGPLv3**（强 copyleft：公网运营派生须开源改动） |
| 主数据库 | PostgreSQL 17 + Redis | SQLite / MySQL / PostgreSQL（默认 SQLite，多实例需换 PG） |
| 部署 | Dockerfile + docker-compose 已具备（自托管为主，仍偏手动运维） | Docker Compose 一键 + 官方镜像 + winget 分发，成熟 |
| 代码规模 | ~46.9k Python + 12.5k Java + 0.4k C + ~1.4k JS/TS（含工具噪声，项目自有 sidecar 数百行）+ ~59k 前端模板 | 成熟单仓库，专注因而精炼 |
| 成熟度 / 社区 | 个人开源项目，功能蔓延，God module | 大型活跃开源，文档全，rc.42 迭代中 |
| 插件系统 | 有（成熟：`plugin/` 双模 sync/aio + zip 包 + 热重载回滚） | 有（**rc.27 起实验性插件系统 + Task Plugins**，仍测试阶段、架构调整大） |

---

## 1.5 多语言原生加速器（APIProxy 新增，2026-10 重构核心）

APIProxy 在 d1cfe0f / 5a969cd / 09eee72 三次提交中落地了多语言架构：

- **C 原生加速器** `native/_apx_native.c`（401 行，编译为 `_apx_native.dll`），通过 `native/__init__.py` 用 ctypes 加载，且提供**纯 Python fallback**（无 C 工具链也能跑）。暴露原语：
  - `apx_fnv1a_64` / `apx_md5_hex` / `apx_sha256_hex`：哈希
  - `apx_constant_time_compare`：常量时间比较（抗侧信道，等价 `secrets.compare_digest`）
  - `apx_sliding_window_allow`：线程安全进程内滑动窗口限流（限流 fallback）
  - `apx_parse_client_hello`：**完整 TLS ClientHello → JA3 元组（string + MD5 + SNI）解析下沉到 C**（之前为 `ja3_threat.py` 纯 Python）
- **Java build pillar** `java/`（12540 行，pom.xml + build.cmd + src/target）：Spring Boot 侧翼，局部能力重写。
- **Node sidecar**（JS/TS）：`09eee72` 引入，负责**通知扇出（notification fan-out）** 与**健康检查面板（health dashboard）**，并承担 `5a969cd` 的 Node 通知扇出与 rate-limit fallback 协同。

意义：CPU 密集与安全敏感原语下沉到 C，带来性能与抗侧信道提升；但维护面从 1 语言扩大到 3+ 语言。

---

## 2. 网关与协议兼容

| 功能 | APIProxy | NewAPI |
|---|---|---|
| 上游类型 | 多 upstream（OpenAI 兼容基址） | 40+ 渠道（OpenAI/Claude/Gemini/DeepSeek/Midjourney/Suno/…） |
| 多上游管理 | 有（`upstreams.py` 339L） | 有（渠道表） |
| 模型映射 / 优先级路由 | 有（`model_mappings` / `routing.py` 234L，优先级+健康度） | 有（自定义映射，加权随机） |
| 故障转移 / failover | 有（链式 fallback） | 有（自动重试+切换） |
| 流式 SSE | 有（透传） | 有 |
| OpenAI Chat Completions | 有（`routes/chat_proxy.py` 509L） | 有 |
| OpenAI Responses API | 有（部分） | 有（并与其他协议互转保留更忠实的工具/引用/grounding 元数据） |
| Anthropic `/v1/messages` | 有（自译 OpenAI；暂不支持 tools） | 原生支持，新增 `POST /v1/messages/count_tokens` |
| **Gemini 协议** | **有（新增 `routes/gemini_compat.py`：generateContent/streamGenerateContent 自译 OpenAI 并复用任务管道；暂不支持原生 tools）** | 有（格式互转，可将 Claude/Gemini 转 OpenAI Responses） |
| Embeddings | 有 | 有 |
| 图像 / 音频 / 视频生成 | **有（images + audio + 新增 videos 三件套；视频复用 images 计费/限流管道，经自定义 httpx 转发上游）** | 有（Midjourney/Suno；**Task Plugins**：MiniMax-H3 视频、xAI Grok Imagine、Seedance 2.0 等） |
| 函数调用 / tool | Chat 路径支持，Claude 兼容层暂不支持 | 支持（跨 relay 路径工具保留更完整） |
| 思维链 / 响应缓存 | 未确认 | 有（Redis 缓存、API 缓存） |
| **WebSearch / WebFetch 工具** | **有（新增 `tools/` 服务端接地：请求带 web_search 类工具时网关先检索、注入 system 上下文再转发上游；默认 DuckDuckGo 无密钥）** | 有（搜索函数计费：per-channel Web search 编码 + 上游回报搜索次数计费） |

> NewAPI 近期（rc.22→rc.42）在协议互转、多模态任务插件、WebSearch 计费上仍领先一截；但 APIProxy 已于 2026-10-13 补齐 **Gemini 原生路由** 与 **服务端 WebSearch 工具**，协议广度从 Chat/Responses/Claude 三件套扩展到四件套。剩余差距主要在多模态生成广度（视频/图像 Task Plugins）、第三方支付、外部 OIDC 登录、套餐订阅。

---

## 3. 计费与配额

| 功能 | APIProxy | NewAPI |
|---|---|---|
| 用户余额账户 | 有（`core_billing.py` 282L，原子预扣/退费） | 有（三阶段计费：预扣→实际→差额） |
| 计费粒度 | 字符计费 + 真实 token 对账 | 按 token（含倍率） |
| 额度上限 / 超支 | 有（`budget.py`） | 有（用户/令牌/分组额度） |
| 价格倍率 | 有（用户组） | 有 |
| 用户组 / 分组 | 有（模型白名单 + 倍率） | 有（令牌分组、可按用户组过滤） |
| 预算告警 / 余额告警 | 有（`balance_alert.py`） | 有 |
| 用量日志 | 有 | 有（详细日志，已做隐私分层：user/admin/root/audit 元数据分离） |
| 充值 | 有（`recharge.py`，自有渠道） | 有（EPay / Stripe / 易支付等） |
| 第三方支付网关 | **无**（无 stripe/epay/alipay/wxpay，仅 `bank_pay.py` 自有） | 有（EPay、Stripe、易支付等） |
| 兑换码 | 有（`redeem.py`） | 有 |
| 订阅 / 套餐 | **有（新增 `subscription.py`：花账户余额扣费，已有同套餐 active 顺延期，余额不足/超支超限整体回滚；管理员 CRUD 套餐 + 用户侧 `/api/subscribe`、`/plans` 页面）** | 有（套餐管理） |
| 防红 / 余额为负保护 | 未确认 | 有 |

---

## 4. 用户、鉴权与权限

| 功能 | APIProxy | NewAPI |
|---|---|---|
| 注册 / 登录 | 有（密码 + 邮箱验证码） | 有（邮箱/密码，可选注册开关） |
| 会话管理 | 有（`core_session.py` 254L） | 有（rc.22 起改为无状态 token + 会话控制） |
| RBAC 角色 | 有（管理员 + 用户组） | 有（用户/管理员/普通用户，系统设置对非 root 管理员隐藏） |
| 用户自建 API Key | 有（`apikey.py` 554L，过期/模型白名单/IP 限制） | 有（令牌，模型限制/过期/IP 限制，组名裁剪修复） |
| 令牌速率限制 | 有（`core_rate_limit.py` + `tokenpolicy.py` RPM/TPM，C 滑动窗口作 fallback） | 有（RPM/TPM） |
| IP 限制 | 有（令牌级 + `ids_ips.py`） | 有（令牌/IP 限制） |
| 多租户 / 子用户 | 用户组近似，无明确子用户 | 有（子用户体系） |
| SSO / OIDC | **有（新增 OIDC 客户端 RP 登录：`oidc.py` + `routes/oidc_routes.py`：discovery + 授权码 PKCE + userinfo + find-or-create 本地用户；管理员 CRUD 提供方，登录页注入外部按钮）** | 有（OIDC 登录） |

---

## 5. OAuth2 服务端（APIProxy 独有优势）

| 功能 | APIProxy | NewAPI |
|---|---|---|
| Authorization Code + PKCE | 有（`oauth.py` 441L / `core_oauth.py`） | 不作为 IdP（是被接入方） |
| ROPC / Client Credentials / Refresh | 有 | — |
| JWT（RS256/HS256，JWKS） | 有（`auth_server.py`：`/jwks` `/introspect` `/revoke` `/userinfo`） | — |
| 令牌内省 / 吊销 | 有 | — |

> 本质差异不变：APIProxy **发行** OAuth2 令牌（给第三方应用发 token），NewAPI 只**消费**上游 OAuth。想做"卖额度给第三方 App"的生意，APIProxy 这点仍是硬优势。

---

## 6. 安全能力（APIProxy 显著更重）

| 功能 | APIProxy | NewAPI |
|---|---|---|
| WAF | 有（`waf.py` 271L） | 基础 |
| CSRF | 有 | 有 |
| IDS / IPS | 有（`ids_ips.py` 533L） | 无 |
| 异常序列检测 | 有（`seq_anomaly.py` 851L） | 无 |
| **JA3 指纹注入 / 校验** | 有（**ClientHello 解析下沉到 C 原生** + `tls_front` 注入，见 §1.5） | 无（上游侧） |
| 蜜罐 | 有（`honeypot.py` 285L） | 无 |
| 熔断 / Kill-switch | 有（`kill_switch.py` 148L） | 无 |
| 泄露守卫 | 有（`leak_guard.py` 266L） | 无 |
| 堡垒机 | 有（`bastion.py` 274L） | 无 |
| 风控 / bot 评分 | 有（`bot_score.py` 154L） | 无 |
| 验证码 + **豁免密钥** | 有（图形 `captcha.py` + 邮箱；新增 `exemption.py` 一次性/ IP 绑定/10 分钟过期豁免密钥） | 有（可选） |
| Cloudflare 集成 | 有（`cloudflare.py` 327L） | 视部署 |
| 审计日志 | 有（`audit_server.py` 248L） | 有（调用审计，隐私分层） |
| IP 地理封锁 / 豁免 | 有（`ip_audit.py` 524L / `exemption.py` 360L） | 无 |

---

## 7. 社交（APIProxy 独有）

| 功能 | APIProxy | NewAPI |
|---|---|---|
| 好友系统 | 有（`social.py` 1116L / `routes/social.py` 1754L） | 无 |
| 动态 / 帖子 | 有 | 无 |
| 通知铃铛 | 有（`notifications_routes.py`，**新增 Node sidecar 通知扇出**） | 无 |
| 公告 | 有（`announcements.py` 256L） | 无 |
| 转账 | 有（社交内） | 无 |

---

## 8. 游戏服 / 运维控制台（APIProxy 独有，但非网关核心）

| 功能 | APIProxy | NewAPI |
|---|---|---|
| RCON 远程控制台 | 有（`core_rcon.py` 1091L / `rcon.py` 1041L / `rcon_server.py` / `rcon_crypto.py` / `core_console.py` 1313L），默认开启 | 不适用 |
| 多节点集群 | 有（`cluster.py` 1059L + `notifications_broadcast.py` 广播） | 无（靠多实例 + Redis/DB 共享） |
| 调度 / 钩子 | 有（`scheduler.py` 897L / `hooks.py` 1237L / `core_tasks.py` 669L） | 无 |

---

## 9. 可观测性与运维

| 功能 | APIProxy | NewAPI |
|---|---|---|
| 健康检查端点 | 有（`health.py`，**新增 Node sidecar 健康面板**） | 有 |
| 用量统计面板 | 有（前端 `modality.py` / `user.py`） | 有（WebUI 用量图表） |
| **Prometheus Metrics** | **有（新增 `utils/metrics.py` + `/metrics` 端点，prometheus_client；上游延迟分位直方图）** | 有 |
| 调用日志查询 | 有（`audit_server.py`） | 有 |
| 管理后台 | 有（`routes/admin.py` 2625L，God module） | 有（完整 WebUI） |
| 多实例水平扩展 | 集群（`cluster.py`，共享 PG+Redis） | 原生（多实例 + DB/Redis 共享状态） |

---

## 10. 插件 / 扩展能力

| 功能 | APIProxy | NewAPI |
|---|---|---|
| 插件运行时 | 有（`plugin/core/manager.py` + `archive.py` + `hotreload.py`） | 有（**rc.27 起实验性插件系统**，含架构性调整，仍测试阶段） |
| 同步 / 异步双 API 面 | 有（`plugin.sync` / `plugin.aio`，单函数双模 `dual()`） | 无（Task Plugin 为主） |
| zip 可分发包 | 有（`DemoPlugin.zip` 直接加载，无需解压） | 无（Task Plugin 上传，源码上限 8 MiB） |
| 热重载（失败回滚） | 有（`hotreload.py`，回滚到上一版源码快照） | 无（实验期不稳定） |
| 资源读取 / 静态路由 | 有（`serve_assets`） | Task Plugin 可声明 `json-order@1` 等扩展点 |
| 任务插件（视频/图像/WebSearch） | ⚠️（WebSearch 服务端接地已实现；视频/图像生成仍无） | 有（MiniMax-H3、Grok Imagine、Seedance、WebSearch 计费等 Task Plugins） |

> 双方都"有插件"，但形态不同：APIProxy 是**面向平台功能的成熟插件框架**（双模 API、zip 包、热重载）；NewAPI 是**面向 relay/任务处理的实验性插件**（视频生成、WebSearch 计费），成熟度与定位不同。

---

## 11. 功能实现情况总表（按"存在性"）

> 图例：✅ 已实现完整 ｜ ⚠️ 部分/雏形 ｜ ❌ 不存在 ｜ — 不适用

| 功能域 | 具体能力 | APIProxy | NewAPI |
|---|---|---|---|
| 网关 | 多上游 + 故障转移 | ✅ | ✅ |
| 网关 | 加权/优先级路由 | ✅(优先级) | ✅(加权随机) |
| 网关 | 密钥池轮换 | ✅ | ✅ |
| 协议 | OpenAI Chat | ✅ | ✅ |
| 协议 | OpenAI Responses | ✅(部分) | ✅ |
| 协议 | Anthropic Messages | ✅(无 tools) | ✅ |
| 协议 | Gemini | ✅(新增原生路由) | ✅ |
| 协议 | Embeddings | ✅ | ✅ |
| 协议 | 图像/音频/视频生成 | ✅(images+audio+videos) | ✅ |
| 协议 | 函数调用 | ✅(Chat) / ⚠️(Claude) | ✅ |
| 协议 | WebSearch / WebFetch | ✅(服务端接地) | ✅ |
| 计费 | 用户余额 | ✅ | ✅ |
| 计费 | 预算/超支 | ✅ | ✅ |
| 计费 | 价格倍率 | ✅ | ✅ |
| 计费 | 充值 | ✅(自有) | ✅(第三方) |
| 计费 | 第三方支付(Stripe/EPay) | ❌ | ✅ |
| 计费 | 兑换码 | ✅ | ✅ |
| 计费 | 套餐/订阅 | ✅(花余额) | ✅ |
| 鉴权 | 注册/登录 | ✅ | ✅ |
| 鉴权 | RBAC | ✅ | ✅ |
| 鉴权 | 用户自建 Key | ✅ | ✅ |
| 鉴权 | 令牌限速 RPM/TPM | ✅ | ✅ |
| 鉴权 | IP 限制 | ✅ | ✅ |
| 鉴权 | 子用户/多租户 | ⚠️(用户组) | ✅ |
| 鉴权 | SSO/OIDC | ✅(新增客户端RP) | ✅ |
| OAuth | 作为 IdP 发行令牌 | ✅(全套) | ❌ |
| 安全 | WAF/IDS/honeypot/JA3/堡垒机/熔断 | ✅(极重) | ⚠️(基础) |
| 安全 | 审计日志 | ✅ | ✅ |
| 社交 | 好友/动态/通知/公告/转账 | ✅ | ❌ |
| 运维 | RCON 控制台 | ✅ | — |
| 运维 | 集群 | ✅(广播) | ❌(多实例代替) |
| 运维 | 调度/钩子 | ✅ | ❌ |
| 可观测 | 健康检查 | ✅ | ✅ |
| 可观测 | **Prometheus metrics** | ✅(新增) | ✅ |
| 可观测 | 用量面板 | ✅ | ✅ |
| 扩展 | 插件系统 | ✅(成熟) | ⚠️(实验性) |
| 扩展 | 热重载 | ✅ | ❌ |
| 扩展 | 任务插件(视频/WebSearch) | ✅(WebSearch + 视频 ✅ / 图像 ❌) | ✅ |
| 部署 | Docker 一键 | ⚠️(有 Dockerfile+compose，成熟度低于 NewAPI) | ✅ |
| 部署 | 多实例 | ✅(集群) | ✅ |

---

## 12. 关键差异解读（更新于 2026-10-13）

1. **许可证实质相反**：APIProxy 现以 **MIT** 开源（派生可闭源商用）；NewAPI 为 **AGPLv3**（公网运营你对它的修改须开源）。若你想 fork NewAPI 改了再公网卖，必须开源改动；APIProxy MIT 无此约束。但反过来说，AGPLv3 让 NewAPI 的"零件"可被社区持续反哺。
2. **插件双方都有，但形态不同**：APIProxy 是**平台级成熟框架**（双模 sync/aio、zip 包、热重载回滚）；NewAPI 是 **rc.27 起的实验性插件 + Task Plugins**（视频/图像/WebSearch 计费），仍测试阶段、架构调整大。原"NewAPI 无插件"结论已失效。
3. **身份角色相反**：APIProxy 是 OAuth **提供方**（发 token 给第三方应用），NewAPI 是 OAuth **消费方**。做 to-C 卖额度生意，APIProxy 仍是硬优势。
4. **计费对象不同**：APIProxy 面向**终端用户**（余额/充值/超支/对账），现已新增 **套餐/订阅（花账户余额扣费）**，但无第三方支付（仅自有 bank_pay）；NewAPI 接 Stripe/EPay，且多了套餐/订阅。
5. **协议广度已大幅收窄**：APIProxy 于 2026-10-13 新增 **Gemini 原生路由** 与 **服务端 WebSearch 工具**，四件套（Chat/Responses/Claude/Gemini）+ WebSearch 已齐；并在当日第三波补齐 **外部 OIDC 客户端登录**（作为 RP 接 GitHub/Google 等）、**套餐/订阅（花账户余额）**、**视频生成（images/audio/videos 三件套）**。剩余差距主要在多模态图像生成广度（图像 Task Plugins）、第三方支付。OAuth 服务端已收紧可申请的敏感 scope（`default` 公开客户端不再发放 `user:write`/`transactions:write`/`apikeys:write`/`rcon`，同意页分区警示高危权限）。
6. **安全权重**：APIProxy 的安全栈（JA3 现已下沉 C 原生解析、IDS/IPS、honeypot、kill-switch、堡垒机、豁免密钥）远超 NewAPI，是 to-C 公网暴露的护城河。
7. **多语言架构是双刃剑**：APIProxy 把哈希/常量时间比较/限流/JA3 解析下沉到 C（401 行 + 纯 Python fallback），性能与抗侧信道提升，但维护面扩到 Python + C + Java(12.5k) + Node。
8. **可观测性补齐**：APIProxy 新增 Prometheus `/metrics`（之前标 ❌，现已 ✅），在指标暴露上追平 NewAPI。

---

## 13. 结论与选型建议

- **想要快速跑稳的多厂商网关**：用 NewAPI（Docker/winget 一键、文档全、40+ 渠道、rc.42 协议/多模态领先、实验性插件可扩展）。
- **想要做 to-C 卖额度的 API 生意**：APIProxy 的零件（计费、OAuth 发行、社交、强安全、C 级性能原语、成熟插件框架）已经现成，且现已 MIT 开源 + 可 Docker 部署，是可行的起点。
- **推荐拓扑**：`Client → APIProxy（平台层：计费/OAuth/社交/安全/C 原生加速）→ NewAPI（网关层：多厂商聚合/故障转移/多模态）→ 厂商`。APIProxy 把 NewAPI 当一个 upstream 接入即可，代价是需处理"双重计费"（NewAPI 侧设为无限额度 token）与"双重 Claude 翻译"（只翻一次）。
- **APIProxy 自身建议**：多语言架构已落地，下一步建议将社交/RCON/集群抽成可选侧翼，聚焦网关+计费+鉴权+安全核心，否则 3+ 语言维护成本会反噬；异步 API 面仍叫 `plugin.aio`（因 `async` 是保留字）。

---

## 14. 本次重对比变更摘要（2026-10-08 → 2026-10-13）

**APIProxy 侧变化：**
- 新增多语言原生架构：C 加速器 `native/_apx_native.c`(401)、Java 侧翼(12540)、Node sidecar（通知扇出 + 健康面板）
- JA3 ClientHello 解析由纯 Python 下沉到 C 原生
- 新增 MIT LICENSE（之前"未声明协议"）
- 新增 Prometheus metrics（`utils/metrics.py` + `/metrics`，之前标 ❌ → ✅）
- 新增 Dockerfile + docker-compose.yml（部署工程化）
- 新增豁免密钥（人机验证一次性豁免）
- 经核查（2026-10-13 早些时候）仍未补上：第三方支付、SSO/OIDC（作为客户端登录）、套餐订阅；Gemini 与 WebSearch 已于当日第二波补齐，OIDC 客户端登录 / 套餐订阅 / 视频生成已于当日第三波补齐（见下）

**NewAPI 侧变化（基于公开 changelog，截至 rc.42）：**
- **rc.27 起引入实验性插件系统 + Task Plugins**（之前"无插件框架" → 现为 ⚠️ 实验性）
- 协议跨 OpenAI/Claude/Gemini 互转、新增 `count_tokens`
- 多模态 Task Plugins：MiniMax-H3、xAI Grok Imagine、Seedance 2.0 视频；Gemini 图像、HEIC/HEIF
- WebSearch 工具 + 搜索函数计费（per-channel 编码 + 上游回报搜索次数）
- 会话改为无状态 token；用量日志隐私分层

**2026-10-13 二次补齐（直接拉平此前标 ❌ 的 Gemini 与 WebSearch 两项）：**
- 新增服务端工具框架 `tools/`：`base.py`(Tool/ToolResult 抽象) + `websearch.py`(WebSearchTool，默认 DuckDuckGo HTML 无密钥，环境变量可切 SerpAPI/Brave) + `grounding.py`(`ground_server_tools` 检测并接地)。
- 接地接入 `core_tasks.py` 的非流式 `_process_task` 与流式 `_process_stream_task`：请求带 `web_search` 类工具（含 OpenAI `web_search_preview` / Anthropic `web_search_20250305`）时，由网关先检索并把结果注入 system 上下文、剥离该工具后转发上游；正常请求零影响（try/except 包裹）。
- 新增 `routes/gemini_compat.py`：Gemini `generateContent`/`streamGenerateContent` 自译为 OpenAI 并复用 `task_manager` 任务管道；另含 `/v1beta/models` 列表端点；已注册 `gemini_bp`。
- 纯单元测试 `tests/test_websearch.py`(5) 与 `tests/test_gemini_translate.py`(5) 全绿。
- 仍缺（待后续补齐，已于当日第三波解决大部分）：第三方支付、外部 OIDC 客户端登录、套餐订阅、视频/图像多模态生成广度。

**2026-10-13 第三波（OIDC 客户端登录 + 套餐/订阅 + 视频多模态 + OAuth 权限收紧）：**
- 新增 **OIDC 客户端 RP 登录**（`oidc.py` + `routes/oidc_routes.py`）：提供方 discovery、授权码 + PKCE、`/oidc/login/<pid>` 重定向、`/oidc/callback/<pid>` 换 token + userinfo + find-or-create 本地用户（按 (provider,sub) 关联 → email 绑定 → 自动建号）；登录页 `/login` 拉 `/login/oidc` JSON 注入外部按钮（中性图标，不复制第三方商标）；管理员 CRUD `/api/admin/oidc/providers`（脱敏不返回 secret）。机密客户端 secret 明文存 `oidc_providers.client_secret`（token 交换必需，admin 接口脱敏）。
- 新增 **套餐/订阅（花账户余额）**（`subscription.py` + `routes/user.py` 的 `/api/plans` `/api/subscribe` `/api/my/subscriptions` `DELETE` + `/plans` 页面 + `routes/admin.py` 套餐 CRUD）：`subscribe()` 单事务原子扣费（查 `balence, allow_overdraft, max_overdraft` → 校验 → 扣费 → 同套餐 active 顺延期，余额不足/超支超限整体 rollback）；`smart_init.py` 建 `subscription_plans` / `user_subscriptions` 表并 seed 默认三档 free(0)/standard(30)/pro(99) 各 30 天。
- 新增 **视频生成多模态**（`configs.py` 加 `MEDIA_PRICING.video_per_unit`；`routes/openai_extra.py` 加 `POST /v1/videos/generations` 复用 images 计费/限流管道；`core_tasks.py` 的 `_process_raw_task`/`_call_raw` 加 `videos` 分支，经自定义 httpx 转发上游，timeout=600）。现 images/audio/videos 三件套齐。
- **收紧 OAuth 可申请的敏感权限**（用户认为原 default 公开客户端"有点危险"）：`oauth.py` 新增 `SENSITIVE_SCOPES=('user:write','transactions:write','apikeys:write','rcon')` 与 `categorize_scopes()`；`DEFAULT_SCOPES` 改为 `DEFAULT_SAFE_SCOPES`（剔除 4 个高危）；`routes/oauth_routes.py` 的 default 分支在授权端点**剥离高危 scope**，且 `rcon` 需 `is_admin` 守卫，同意页分区（`.scope.danger` 红 + 警示块）渲染高危权限。
- 测试全绿：`tests/test_oauth_scopes.py`(4) + `tests/test_oidc.py`(4) + `tests/test_multimodal.py`(3) + `tests/test_subscription.py`(4) = 15 例全绿（pytest 须在 `E:/Code` 跑 + `--noconftest`）。
- 仍缺（待后续）：第三方支付（Stripe/EPay/alipay/wxpay）、图像生成 Task Plugins 广度。

---

*附：APIProxy 重点证据文件*
- 多语言：`native/_apx_native.c`(401)、`native/__init__.py`、`native/build_native.py`、`java/`(12540)、`ja3.py`
- 网关/路由/工具：`upstreams.py`(339)、`routing.py`(234)、`routes/chat_proxy.py`(509)、`routes/claude_compat.py`(277)、`routes/gemini_compat.py`(新增)、`routes/_gemini_translate.py`(新增)、`tools/`(WebSearch 服务端接地框架)
- 计费：`core_billing.py`(282)、`pricing.py`(310)、`budget.py`、`recharge.py`、`redeem.py`(150)、`balance_alert.py`、`bank_pay.py`(107)
- 鉴权/OAuth：`apikey.py`(554)、`core_auth.py`、`core_session.py`(254)、`oauth.py`(441)、`core_oauth.py`、`auth_server.py`
- 安全：`security_middleware.py`(1497)、`waf.py`(271)、`ids_ips.py`(533)、`seq_anomaly.py`(851)、`ja3_threat.py`(208)、`kill_switch.py`(148)、`leak_guard.py`(266)、`honeypot.py`(285)、`bastion.py`(274)、`bot_score.py`(154)、`cloudflare.py`(327)、`exemption.py`(360)
- 社交：`social.py`(1116)、`routes/social.py`(1754)、`announcements.py`(256)
- RCON/集群：`core_rcon.py`(1091)、`rcon.py`(1041)、`rcon_crypto.py`(309)、`core_console.py`(1313)、`cluster.py`(1059)、`notifications_broadcast.py`
- 可观测/插件：`utils/metrics.py`、`plugin/core/manager.py`(424)、`plugin/core/archive.py`(557)、`plugin/core/hotreload.py`(415)
- 管理/God module：`routes/admin.py`(2625)
- 工程化：`Dockerfile`、`docker-compose.yml`、`LICENSE`(MIT)、`README.md`、`EXEMPTION_INTEGRATION_GUIDE.md`
- 2026-10-13 第三波（OIDC + 套餐订阅 + 视频多模态 + OAuth 收紧）：`oidc.py`、`routes/oidc_routes.py`、`templates/login.html`(外部按钮)、`templates/oidc_login.html`、`subscription.py`、`routes/user.py`(`/api/plans` `/api/subscribe` `/plans`)、`routes/admin.py`(套餐 CRUD)、`configs.py`(`MEDIA_PRICING.video_per_unit`)、`routes/openai_extra.py`(`/v1/videos/generations`)、`core_tasks.py`(videos 分支)、`oauth.py`(`SENSITIVE_SCOPES`/`categorize_scopes`)、`routes/oauth_routes.py`(剥离高危 scope)、`tests/test_oauth_scopes.py`(4)/`tests/test_oidc.py`(4)/`tests/test_multimodal.py`(3)/`tests/test_subscription.py`(4)
