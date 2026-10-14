# APIProxy Java 版（完整迁移）

基于 Spring Boot 3.4 的 API 网关，从 Python 版完整功能迁移。

## 技术栈
- Java 21 LTS + Spring Boot 3.4.0
- Spring Security 6（表单登录 + CSRF + 会话管理）
- Spring Data JPA + PostgreSQL
- Spring WebFlux（WebClient 上游流式代理）
- Thymeleaf（35 个页面模板）
- JJWT（OAuth2 JWT）
- BouncyCastle（兼容 Python bcrypt/scrypt/pbkdf2 密码哈希）
- Lombok

## 功能模块（18 个 Controller + 22 个 Service）

### 核心业务
| 模块 | Controller | Service | 说明 |
|------|-----------|---------|------|
| 认证 | AuthController | AuthService | 注册/登录/密码重置/修改密码 |
| 用户 | UserController | UserService | 用户信息/设置/余额 |
| API Key | ApiKeyController | ApiKeyService | API 密钥 CRUD/限流 |
| 计费 | BillingController | BillingService + PricingService | 余额扣费/定价/充值审核 |
| 代理 | ChatProxyController | ProxyService + UpstreamService | OpenAI 兼容 API 流式代理 |
| OAuth2 | OAuthController | OAuthService | 授权码/设备码/客户端凭证流程 |
| 通知 | NotificationController | NotificationService | SSE 实时通知推送 |

### 管理与运维
| 模块 | Controller | Service | 说明 |
|------|-----------|---------|------|
| 管理后台 | AdminController | AdminService | 用户/公告/IP封禁/设备封禁/Hooks/帖子/任务/审计/配置/上游/定价 |
| 审计日志 | AuditController | AuditService | 审计日志/登录日志/Web访问日志/统计 |
| 集群 | ClusterController | ClusterService | 节点注册/心跳/领导者选举/配置同步 |
| 控制台 | ConsoleController | ConsoleService | KV配置/系统信息/命令执行 |
| 邮箱验证码 | EmailCaptchaController | EmailCaptchaService | 验证码发送/校验/限流 |
| 健康检查 | HealthController | - | liveness/readiness/详细状态 |
| 页面渲染 | PagesController | - | 35+ 页面 Thymeleaf 路由 |
| Debug Console | DebugConsoleController | DebugConsoleService | Minecraft Debug Console协议/密钥/会话/加密 |
| 充值 | RechargeController | RechargeService | 充值订单/支付回调/管理员审核/交易记录 |
| 社交 | SocialController | SocialService | 帖子/点赞/收藏/好友/私信/转账 |

### 安全基础设施
| 模块 | 类 | 说明 |
|------|-----|------|
| WAF | WafService + WafFilter | SQLi/XSS/路径遍历/扫描器/恶意UA/Host校验/请求体大小/全局RPM/违规自动封禁 |
| IDS/IPS | IdsIpsService + IdsIpsFilter | Log4j/JNDI/RCE/SSTI/SSRF/NoSQL/XXE/PHP包装器/WebShell/HTTP走私/异常动词/端点枚举/认证暴破 |
| WebFilter | WebFilterService + WebFilterInterceptor | URL分类(恶意/钓鱼/赌博/成人/代理/社交/流媒体/广告)/分类拦截/管理员豁免/全站行为审计 |
| Hooks DSL | HooksEngineService | 事件驱动DSL引擎/条件评估(and/or/not/eq/ne/gt/lt/regex/contains/in)/动作执行(block/redirect/set_header/set_var/log/notify/webhook)/执行日志 |
| 定时任务 | SchedulerService | 持久化任务调度/cron表达式/固定频率/执行日志/内置任务(清理/通知/计费/备份/健康检查/集群同步/上游刷新/日志轮转)/线程池 |

## 数据层
- 39 个 JPA Entity（对应 PostgreSQL 表）
- 39 个 Spring Data Repository
- 数据库 Schema 由 Alembic 管理，JPA 设为 `ddl-auto: validate`

## 前端
- 35 个 Thymeleaf HTML 模板（从 Python Jinja2 模板迁移）
- 覆盖：登录/注册/忘记密码/仪表盘/设置/聊天/社区/好友/通知/文档/社交全套/OAuth全套/Debug Console/管理后台全套

## 构建与运行
```bash
# 编译
mvn compile

# 打包（跳过测试）
mvn package -DskipTests

# 运行
java -jar target/apiproxy-1.0.0.jar
```

## 配置
配置文件：`src/main/resources/application.yml`
- 端口：5000（与 Python 版一致）
- 数据库：PostgreSQL
- 会话超时：24h
- 支持环境变量覆盖：DB_PASSWORD, OAUTH_JWT_SECRET

## 代码统计
- Java 源文件：138 个
- 代码行数：12,526 行
- HTML 模板：35 个
- 可执行 JAR：73 MB
