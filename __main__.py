"""APIProxy 应用入口。

职责仅限于「初始化与挂载」：
  1. 组装应用（中间件 / 蓝图 / 错误处理器）
  2. 启动前校验（fail-closed 密钥检查、敏感文件权限收紧）
  3. 数据库 schema 初始化与运行期表准备
  4. 拉起后台服务（上游刷新、计费表、RCON、调度器）
  5. 启动 Web 服务（HTTP 或 HTTPS）

业务逻辑分布在：
  app.py                        Quart 实例与 session 配置
  core.py                       跨模块共享的工具与状态
  routes/                       按域拆分的蓝图
  middleware/security_middleware.py   WAF / CSRF / 安全响应头
  utils/errors.py               统一错误处理
"""
import asyncio
import logging
import os
import sys

# ── 可选：VirtualRouter / Floyd 虚拟网络劫持 ──
# 设置 FLOYD_ENABLE=1 时，在任何网络库 import 之前安装 FloydSocket，
# 让本进程透明跑在 VirtualRouter 的虚拟网络（跨网段/多设备模拟）。
# 必须在 import socket 的库（asyncio 等）之前完成，故放最顶部。
if os.getenv("FLOYD_ENABLE") == "1":
    _floyd_root = os.getenv("FLOYD_ROOT", r"E:/Code")
    if _floyd_root not in sys.path:
        sys.path.insert(0, _floyd_root)
    try:
        from VirtualRouter.floyd import install as _floyd_install
        _floyd_install()
        logging.getLogger(__name__).info("Floyd 虚拟网络已安装（进程已挂到 VirtualRouter）")
        # 可选：把本进程虚拟 IP 落盘，便于跨网段模拟脚本获取 LB 地址
        _ip_dump = os.getenv("FLOYD_DUMP_IP")
        if _ip_dump:
            try:
                from VirtualRouter.floyd import _floyd_listen_ip
                with open(_ip_dump, "w", encoding="utf-8") as _f:
                    _f.write(_floyd_listen_ip or "")
            except Exception as _e2:
                logging.getLogger(__name__).warning("Floyd IP dump 失败：%s", _e2)
    except Exception as _e:
        logging.getLogger(__name__).error("Floyd 安装失败：%s", _e)

from .app import app, BASE_DIR
from .configs import DB_PATH, OAUTH_JWT_SECRET, SSL_ENABLED
from . import configs
from . import core
from . import pricing
from . import upstreams
from .utils.logging_setup import setup_logging

# 统一日志配置（支持 LOG_FORMAT=json / text，LOG_LEVEL 可调）
setup_logging()

logger = logging.getLogger(__name__)

APP_VERSION = "1.0.0"


# ============================================================================
# 应用组装
# ============================================================================

_APP_BUILT = False


def create_app():
    """挂载中间件、蓝图与错误处理器，返回可服务的 app 实例。

    幂等：重复调用（测试 / 热重载场景）不会重复注册中间件、蓝图，
    避免 Quart 抛 ``View function mapping is overwriting an existing endpoint``。
    """
    global _APP_BUILT
    if _APP_BUILT:
        return app

    from .middleware.security_middleware import register_middleware
    from .routes import register_blueprints
    from .utils.endpoints import register_endpoint_aliases
    from .utils.errors import register_error_handlers
    from .utils.metrics import setup_metrics

    # CSP nonce 注入所有模板（配合移除 'unsafe-inline'）
    from quart import g

    @app.context_processor
    async def _inject_csp_nonce():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    # 指标追踪需最先注册，确保 before_request 记录到完整请求延迟
    setup_metrics(app)
    register_middleware(app)
    register_blueprints(app)
    register_error_handlers(app)

    # 蓝图化后 endpoint 带前缀，兼容历史裸名 url_for 调用
    register_endpoint_aliases(app)

    # 插件系统：挂载 plugins/ 目录下的插件。
    # 放在蓝图之后，使插件在 app 就绪后注册自己的路由；单个插件失败不致命。
    try:
        from .plugin import load_plugins, attach_hot_reload
        load_plugins(app)
        # 热重载默认关闭；开启后会在 before_serving 里拿到服务循环再启动巡检，
        # 保证路由变更始终发生在事件循环线程内。
        attach_hot_reload(app)
        logger.info("Plugin system initialized")
    except Exception as e:
        logger.error(f"Failed to initialize plugin system: {e}")

    # hooks / announcements 的依赖注入（需在蓝图导入之后）
    core.init_integrations()

    # 调度器自带路由，单独注册（失败不致命）
    try:
        from .scheduler import register_scheduler_routes
        register_scheduler_routes(app)
        logger.info("Scheduler routes registered")
    except Exception as e:
        logger.error(f"Failed to register scheduler routes: {e}")

    _APP_BUILT = True
    return app


# ============================================================================
# 启动前校验
# ============================================================================

def preflight_checks() -> None:
    """启动前的 fail-closed 校验。任一硬性条件不满足则拒绝启动。"""
    # OAuth JWT 签名密钥必须显式配置，缺失则拒绝启动，
    # 避免回退到不安全默认值而静默签发 / 验签令牌。
    if not OAUTH_JWT_SECRET:
        logger.critical(
            "OAUTH_JWT_SECRET is not set. Refusing to start (fail-closed). "
            'Generate one with: python -c "import secrets; print(secrets.token_hex(32))" '
            "then set it via env APIPROXY_OAUTH_JWT_SECRET or config.yaml."
        )
        raise SystemExit(1)

    # 非致命：缺失的可选密钥仅告警
    try:
        for warning in configs.check_secrets():
            logger.warning(warning)
    except AttributeError:
        pass


def harden_file_permissions() -> None:
    """收紧敏感文件权限至仅所有者可读写（Windows 下尽力而为）。"""
    targets = (
        DB_PATH,
        getattr(configs, 'CONFIG_PATH', None),
        os.path.join(os.path.dirname(__file__), '.session_secret'),
        os.path.join(os.path.dirname(__file__), '.rcon_key'),
    )
    for path in targets:
        try:
            if path and os.path.exists(path):
                os.chmod(path, 0o600)
        except Exception:
            pass


# ============================================================================
# 初始化
# ============================================================================

def init_database() -> None:
    """完整 schema 初始化 + 运行期表准备。

    优先用 Alembic 迁移（基线复用 smart_init 建表，记录 schema 版本）；
    Alembic 失败时回退到 smart_init 幂等建表，保证老部署不受影响。
    """
    migrated = False
    try:
        from alembic.config import Config as AlembicConfig
        from alembic import command as alembic_command
        cfg = AlembicConfig(os.path.join(BASE_DIR, "alembic.ini"))
        alembic_command.upgrade(cfg, "head")
        migrated = True
        logger.info("Database schema migrated via Alembic")
    except Exception as e:
        logger.error(f"Alembic migration failed, falling back to smart_init: {e}")

    if not migrated:
        try:
            from . import smart_init
            smart_init.smart_init()
        except Exception as e:
            logger.error(f"smart_init failed: {e}")

    core._init_sessions_table()
    core._init_rate_limit_table()

    # 安全子系统审计表（上网行为 / 堡垒机 / 审计服务器 / 认证服务器）
    try:
        from .init_db import ensure_subsystem_tables
        ensure_subsystem_tables()
    except Exception as e:
        logger.error(f"ensure_subsystem_tables failed: {e}")

    # 清理历史残留，避免表无限增长
    for cleanup in (core._cleanup_rate_limits_sync, core._cleanup_expired_sessions_sync):
        try:
            cleanup()
        except Exception as e:
            logger.warning(f"{cleanup.__name__} failed: {e}")


def start_background_services() -> None:
    """拉起后台服务，各项失败均不致命。"""
    # 系统虚拟用户（UID 池 0~15）最先落库，保证后续通知有真实发件人可进聊天
    try:
        from . import system_users as _su
        asyncio.run(_su.ensure_system_users())
        logger.info("System virtual users ensured")
    except Exception as e:
        logger.error(f"ensure_system_users failed: {e}")

    try:
        asyncio.run(upstreams.startup_refresh())
        logger.info("Upstream clients initialized and model catalog refreshed")
    except Exception as e:
        logger.error(f"Upstream startup refresh failed: {e}")

    try:
        rows = pricing.reload_pricing_from_db()
        logger.info(f"Pricing schedules loaded from DB: {rows} rows")
    except Exception as e:
        logger.error(f"Pricing reload from DB failed: {e}")

    try:
        core._start_rcon_server_thread()
        logger.info("RCON server starting")
    except Exception as e:
        logger.error(f"Failed to start RCON server: {e}")

    try:
        from .scheduler import start_scheduler
        start_scheduler()
        logger.info("Task scheduler started")
    except Exception as e:
        logger.error(f"Failed to start task scheduler: {e}")

    try:
        from .routing import start_health_prober
        start_health_prober()
        logger.info("Upstream health prober started")
    except Exception as e:
        logger.error(f"Failed to start upstream health prober: {e}")

    try:
        from .pg_backup import start_backup_loop
        try:
            from .ops_settings import apply_overrides
            apply_overrides()   # WebUI 保存过的运维设置（DB）覆盖 config.yaml
        except Exception as e:
            logger.error(f"Failed to apply ops_settings overrides: {e}")
        start_backup_loop()
    except Exception as e:
        logger.error(f"Failed to start db backup scheduler: {e}")

    try:
        from .retention import start_retention_loop
        start_retention_loop()
    except Exception as e:
        logger.error(f"Failed to start log retention scheduler: {e}")

    try:
        from .cluster import cluster
        cluster.start()
        logger.info("Cluster discovery started")
    except Exception as e:
        logger.error(f"Failed to start cluster discovery: {e}")

    # 启动接口自检（目标 4.1）：对全部 GET 路由冒烟探测，结果缓存 10 分钟
    if getattr(configs, "SELFTEST_ENABLED", True):
        try:
            from . import selftest
            asyncio.run(selftest.run_endpoint_selftest())
            logger.info("Startup endpoint self-test completed")
        except Exception as e:
            logger.error(f"Startup self-test failed: {e}")


# ============================================================================
# TLS
# ============================================================================

def ensure_self_signed_cert(cert_path: str, key_path: str) -> None:
    """证书或私钥缺失时生成自签名证书（仅用于本地 / 内网调试）。"""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    logger.info("Auto-generating self-signed TLS certificate")
    import datetime as dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    os.makedirs(os.path.dirname(cert_path), exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'CN'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Cloud LLM API Proxy'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    logger.info(f"Self-signed cert generated: {cert_path}")


# ============================================================================
# 服务启动
# ============================================================================

def serve_https() -> None:
    from hypercorn.asyncio import serve
    from hypercorn.config import Config as HyperConfig
    from .configs import HTTPS_PORT, SSL_CERT, SSL_KEY, BIND_HOST, WEB_MAX_REQUESTS

    cert_path = SSL_CERT or os.path.join(BASE_DIR, 'certs', 'server.crt')
    key_path = SSL_KEY or os.path.join(BASE_DIR, 'certs', 'server.key')
    ensure_self_signed_cert(cert_path, key_path)

    config = HyperConfig()
    config.bind = [f"{BIND_HOST}:{HTTPS_PORT}"]
    config.certfile = cert_path
    config.keyfile = key_path
    config.ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    config.accesslog = "-"
    config.errorlog = "-"
    config.ssl_handshake_timeout = 60
    # 优雅停机：收到 SIGTERM/SIGINT 后最多等待 30s 让在途请求完成再退出
    config.graceful_timeout = float(os.getenv('GRACEFUL_TIMEOUT', '30'))
    config.keep_alive_timeout = 5
    # 生产并发：默认按 CPU 核数起 worker，可用 WEB_CONCURRENCY 覆盖
    config.workers = int(os.getenv('WEB_CONCURRENCY', '1'))
    # worker 回收：每处理 N 个请求后自动重启该 worker，缓解长周期内存泄漏/资源滞留。
    # 可用 --web-max-requests / 配置文件 / APIPROXY_WEB_MAX_REQUESTS 环境变量设置。
    # 注意：Hypercorn 语义中 None 才是「关闭」；若传 0，首个请求完成后即触发优雅
    # 停机，进程静默退出（退出码 0、无任何日志）——gunicorn 的「0=关闭」语义
    # 必须在这里显式翻译成 None。
    _max_requests = int(WEB_MAX_REQUESTS)
    config.max_requests = _max_requests if _max_requests > 0 else None
    # config.yaml 的 hypercorn: 段优先级最高，覆盖以上所有代码默认值
    _apply_hypercorn_file_config(config)

    logger.info(f"HTTPS enabled, listening on port {HTTPS_PORT} (TLS 1.2/1.3)")
    asyncio.run(serve(app, config))


def _pick_random_port() -> int:
    """分配一个可用的随机端口（集群 Worker 使用，避免对外固定端口）。"""
    import random
    import socket
    for _ in range(50):
        port = random.randint(10000, 60000)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("0.0.0.0", port))
            s.close()
            return port
        except OSError:
            continue
    raise RuntimeError("无法分配随机端口")


def serve_http() -> None:
    from . import configs
    from . import cluster
    from .cluster import set_node_port

    # 确定服务端口：集群 LB 固定端口；集群 Worker 随机端口（由 LB 路由）；
    # 单机模式用 PORT 环境变量。角色由自适应选举（cluster.role）决定，
    # 选举已在 start_background_services() -> cluster.start() 中完成。
    if configs.CLUSTER_ENABLED:
        role = getattr(cluster, "role", None)
        if role == "lb":
            port = configs.CLUSTER_LB_PORT
        else:
            # Worker（含晋升前的独立/Worker 节点）
            port = configs.CLUSTER_NODE_PORT or _pick_random_port()
    else:
        port = configs.PORT
    set_node_port(port)

    # 生产环境必须关闭 debug，防止交互式调试器导致远程代码执行
    debug_mode = configs.DEBUG
    if debug_mode:
        logger.warning("DEBUG mode is ON — never enable this in production")
    logger.info(f"HTTP listening on {configs.BIND_HOST}:{port}")

    # 集群管理令牌（每次启动随机生成）：访问 /cluster/* 管理端点需携带
    # ?token=<token> 或先在 /cluster/login 页面点击「登录」建立会话。
    from .cluster import get_cluster_token
    logger.info("集群管理令牌 CLUSTER_TOKEN = %s", get_cluster_token())

    # 虚拟网络模式（CLUSTER_VNET=1）：把本进程虚拟 IP 落盘路径透传给集群层，
    # 由 cluster._tcp_listen_loop 在真正监听后写入实际虚拟 IP（供 Worker 获取 LB 地址）。
    # 这里只设置环境变量，集群层负责实际写入。

    # 生产 ASGI 服务器：用 Hypercorn 启动 HTTP 服务（而非 Quart 自带的 Werkzeug 开发服务器）。
    # HTTPS 模式本就走 Hypercorn；此分支让 HTTP 模式也能用上 worker 并发/优雅停机等生产特性。
    if configs.HYPERCORN_ENABLED:
        _serve_http_hypercorn(configs.BIND_HOST, port, debug_mode)
        return

    app.run(host=configs.BIND_HOST, port=port, debug=debug_mode)


def _apply_hypercorn_file_config(cfg) -> None:
    """把 config.yaml 的 hypercorn: 段合并进 Hypercorn Config（段内值优先级最高）。

    键名即 hypercorn.config.Config 的属性名；未知键告警并忽略
    （Hypercorn 对 setattr 未知键会静默挂上无效属性，这里显式拦截防手误）。
    """
    from . import configs
    from hypercorn.config import Config as HyperConfig

    section = getattr(configs, "HYPERCORN_CONFIG", None) or {}
    if not isinstance(section, dict):
        return
    for key, value in section.items():
        if not hasattr(HyperConfig, key):
            logger.warning("config.yaml hypercorn: 段忽略未知键: %s", key)
            continue
        setattr(cfg, key, value)


def _serve_http_hypercorn(host: str, port: int, debug: bool) -> None:
    """HTTP 模式用 Hypercorn（ASGI 生产服务器）真正监听并服务。"""
    from . import configs
    from hypercorn.asyncio import serve
    from hypercorn.config import Config as HyperConfig

    if debug:
        # Hypercorn 没有 Werkzeug 那种交互式调试器，仅给出提示，不阻断启动。
        logger.warning("DEBUG 模式在 Hypercorn 下无交互式调试器（仍关闭生产 RCE 风险）")

    cfg = HyperConfig()
    cfg.bind = [f"{host}:{port}"]
    cfg.accesslog = "-"
    cfg.errorlog = "-"
    # 优雅停机：收到 SIGTERM/SIGINT 后最多等待 30s 让在途请求完成再退出
    cfg.graceful_timeout = float(os.getenv('GRACEFUL_TIMEOUT', '30'))
    cfg.keep_alive_timeout = 5
    # 生产并发：默认单 worker（HTTP 单机），可用 WEB_CONCURRENCY 覆盖
    cfg.workers = int(os.getenv('WEB_CONCURRENCY', '1'))
    # worker 回收：每处理 N 个请求后自动重启该 worker。
    # Hypercorn 语义：None=关闭；传 0 会导致首请求后进程静默退出（见 serve_https 注释）。
    _max_requests = int(configs.WEB_MAX_REQUESTS)
    cfg.max_requests = _max_requests if _max_requests > 0 else None
    # config.yaml 的 hypercorn: 段优先级最高，覆盖以上所有代码默认值
    _apply_hypercorn_file_config(cfg)

    logger.info("HTTP 服务经由 Hypercorn 启动（ASGI 生产服务器）")
    asyncio.run(serve(app, cfg))


def _build_arg_parser() -> "argparse.ArgumentParser":
    """构建完整的命令行参数解析器（覆盖 configs.py 的主要配置项）。

    约定：每个 flag 的 dest 直接对应 configs 中的大写配置项名，
    便于 main() 直接组装成 overrides 传给 configs.apply_cli_overrides()。
    布尔项统一用 BooleanOptionalAction（--x / --no-x），未提供时为 None（不覆盖）。
    """
    import argparse

    p = argparse.ArgumentParser(
        prog="APIProxy",
        description="Cloud LLM API Proxy 服务端",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=True,
    )

    # ---- 通用 / 服务绑定 ----
    g = p.add_argument_group("通用 / 服务绑定")
    g.add_argument("--host", dest="BIND_HOST", default=None,
                   help="HTTP/HTTPS 监听地址（默认 0.0.0.0）")
    g.add_argument("--port", dest="PORT", type=int, default=None,
                   help="单机模式 HTTP 端口（覆盖 PORT 环境变量，默认 5000）")
    g.add_argument("--debug", action=argparse.BooleanOptionalAction, dest="DEBUG", default=None,
                   help="开启 Quart 调试模式（生产环境禁止）")
    g.add_argument("--log-level", dest="log_level",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default=None,
                   help="日志级别")
    g.add_argument("--print-config", action="store_true", dest="print_config",
                   help="打印生效配置（密钥脱敏）后退出")
    g.add_argument("--version", action="store_true", dest="version",
                   help="打印版本号后退出")

    # ---- 数据库 / 缓存 ----
    g = p.add_argument_group("数据库 / 缓存")
    g.add_argument("--db-path", dest="DB_PATH", default=None, help="SQLite 数据库文件路径")
    g.add_argument("--db-type", dest="DB_TYPE", choices=["sqlite", "postgres"], default=None,
                   help="数据库后端类型")
    g.add_argument("--database-url", dest="DATABASE_URL", default=None,
                   help="PostgreSQL 连接串（DB_TYPE=postgres 时生效）")
    g.add_argument("--redis-url", dest="REDIS_URL", default=None,
                   help="Redis 连接串（限流/缓存加速，留空回退 SQLite）")

    # ---- 密钥 / 上游 ----
    g = p.add_argument_group("密钥 / 上游 API")
    g.add_argument("--baseurl", dest="BASEURL", default=None, help="上游 API base_url")
    g.add_argument("--apikey", dest="APIKEY", default=None, help="上游 API key")
    g.add_argument("--session-secret", dest="SESSION_SECRET", default=None, help="会话签名密钥")
    g.add_argument("--token-secret", dest="TOKEN_SECRET", default=None, help="令牌签名密钥")
    g.add_argument("--oauth-jwt-secret", dest="OAUTH_JWT_SECRET", default=None,
                   help="OAuth JWT 签名密钥（缺失则 fail-closed）")
    g.add_argument("--oauth-registration-open", action=argparse.BooleanOptionalAction,
                   dest="OAUTH_REGISTRATION_OPEN", default=None, help="是否开放 OAuth 注册")

    # ---- 集群 / 自动角色切换 ----
    g = p.add_argument_group("集群 / 自动角色切换")
    g.add_argument("--cluster-enabled", action=argparse.BooleanOptionalAction,
                   dest="CLUSTER_ENABLED", default=None, help="启用分布式集群")
    g.add_argument("--cluster-role", dest="CLUSTER_ROLE", choices=["lb", "worker"], default=None,
                   help="静态集群角色（兼容旧部署；未设 --cluster-mode 时决定模式）")
    g.add_argument("--cluster-mode", dest="CLUSTER_MODE", choices=["auto", "lb", "worker"],
                   default=None, help="集群模式：auto=自适应选举，lb/worker=静态")
    g.add_argument("--cluster-transport", dest="CLUSTER_TRANSPORT",
                   choices=["multicast", "tcp"], default=None, help="集群传输层")
    g.add_argument("--cluster-group", dest="CLUSTER_GROUP", default=None, help="组播地址（multicast 模式）")
    g.add_argument("--cluster-port", dest="CLUSTER_PORT", type=int, default=None, help="组播端口")
    g.add_argument("--cluster-tcp-port", dest="CLUSTER_TCP_PORT", type=int, default=None,
                   help="TCP 注册端口（tcp 模式，LB 监听）")
    g.add_argument("--cluster-lb-host", dest="CLUSTER_LB_HOST", default=None,
                   help="Worker 连接 LB 的地址（tcp 模式；留空取本机 IP）")
    g.add_argument("--cluster-vnet", action=argparse.BooleanOptionalAction, dest="CLUSTER_VNET",
                   default=None, help="虚拟网络模式（跨网段模拟）")
    g.add_argument("--cluster-interval", dest="CLUSTER_INTERVAL", type=int, default=None,
                   help="心跳间隔（秒）")
    g.add_argument("--cluster-lb-port", dest="CLUSTER_LB_PORT", type=int, default=None,
                   help="LB 对外固定端口")
    g.add_argument("--cluster-node-port", dest="CLUSTER_NODE_PORT", type=int, default=None,
                   help="Worker 服务端口（0=随机）")
    g.add_argument("--cluster-worker-timeout", dest="CLUSTER_WORKER_TIMEOUT", type=int, default=None,
                   help="Worker 超时秒数（失联后重选举/退出）")
    g.add_argument("--cluster-bootstrap-wait", dest="CLUSTER_BOOTSTRAP_WAIT", type=int, default=None,
                   help="选举/发现窗口（秒）")
    g.add_argument("--static-role", dest="CLUSTER_STATIC_ROLE", choices=["worker", "lb"],
                   default=None, help="强制指定角色（覆盖自适应选举）；不指定则动态获得/转换")
    g.add_argument("--cluster-secret", dest="CLUSTER_SECRET", default=None,
                   help="集群节点间消息鉴权共享密钥（也可用 CLUSTER_SECRET 环境变量）")

    # ---- HTTPS / SSL ----
    g = p.add_argument_group("HTTPS / SSL")
    g.add_argument("--ssl-enabled", action=argparse.BooleanOptionalAction, dest="SSL_ENABLED",
                   default=None, help="启用 HTTPS（TLS）")
    g.add_argument("--ssl-cert", dest="SSL_CERT", default=None, help="TLS 证书路径")
    g.add_argument("--ssl-key", dest="SSL_KEY", default=None, help="TLS 私钥路径")
    g.add_argument("--https-port", dest="HTTPS_PORT", type=int, default=None, help="HTTPS 监听端口")
    g.add_argument("--hypercorn", action=argparse.BooleanOptionalAction, dest="HYPERCORN_ENABLED",
                   default=None, help="HTTP 模式改用 Hypercorn（ASGI 生产服务器）启动，而非 Quart 自带开发服务器（HTTPS 模式本就使用 Hypercorn）")
    g.add_argument("--web-max-requests", dest="WEB_MAX_REQUESTS", type=int, default=None,
                   help="Hypercorn worker 回收阈值：每处理 N 个请求后自动重启该 worker（0=关闭，默认）")

    # ---- WAF / 安全 ----
    g = p.add_argument_group("WAF / 安全")
    g.add_argument("--waf-enabled", action=argparse.BooleanOptionalAction, dest="WAF_ENABLED",
                   default=None, help="启用 Web 应用防火墙")
    g.add_argument("--waf-disable-if-cloudflare", action=argparse.BooleanOptionalAction,
                   dest="WAF_DISABLE_IF_CLOUDFLARE", default=None, help="Cloudflare 后关闭 WAF")
    g.add_argument("--waf-max-body-bytes", dest="WAF_MAX_BODY_BYTES", type=int, default=None,
                   help="WAF 请求体最大字节数")
    g.add_argument("--waf-allowed-hosts", dest="WAF_ALLOWED_HOSTS", default=None,
                   help="WAF 允许的主机列表（逗号分隔）")
    g.add_argument("--waf-global-rpm", dest="WAF_GLOBAL_RPM", type=int, default=None,
                   help="WAF 全局每分钟请求上限")
    g.add_argument("--waf-violations-rpm", dest="WAF_VIOLATIONS_RPM", type=int, default=None,
                   help="WAF 违规每分钟上限")
    g.add_argument("--waf-ban-minutes", dest="WAF_BAN_MINUTES", type=int, default=None,
                   help="WAF 封禁时长（分钟）")

    # ---- IDS / IPS 入侵检测与防御 ----
    g = p.add_argument_group("IDS / IPS 入侵检测与防御")
    g.add_argument("--ids-ips-enabled", action=argparse.BooleanOptionalAction,
                   dest="IDS_IPS_ENABLED", default=None, help="启用 IDS/IPS 入侵检测与防御")
    g.add_argument("--ids-ips-mode", dest="IDS_IPS_MODE",
                   choices=["detect", "prevent"], default=None,
                   help="运行模式：detect=仅记录告警，prevent=拦截并自动封禁（默认 prevent）")
    g.add_argument("--ids-ips-ban-on-critical", action=argparse.BooleanOptionalAction,
                   dest="IDS_IPS_BAN_ON_CRITICAL", default=None,
                   help="命中严重签名（如 Log4j/RCE）时立即封禁 IP")
    g.add_argument("--ids-ips-ban-minutes", dest="IDS_IPS_BAN_MINUTES", type=int, default=None,
                   help="IDS/IPS 自动封禁时长（分钟）")
    g.add_argument("--ids-ips-scan-paths", dest="IDS_IPS_SCAN_PATHS", type=int, default=None,
                   help="端点扫描判定：窗口内不同 404 路径数量阈值")
    g.add_argument("--ids-ips-scan-window", dest="IDS_IPS_SCAN_WINDOW", type=int, default=None,
                   help="端点扫描滑动窗口（秒）")
    g.add_argument("--ids-ips-authfail-threshold", dest="IDS_IPS_AUTHFAIL_THRESHOLD",
                   type=int, default=None, help="认证暴破判定：窗口内登录失败次数阈值")
    g.add_argument("--ids-ips-authfail-window", dest="IDS_IPS_AUTHFAIL_WINDOW", type=int, default=None,
                   help="认证暴破滑动窗口（秒）")
    g.add_argument("--ids-ips-block-score", dest="IDS_IPS_BLOCK_SCORE", type=int, default=None,
                   help="累计风险分超此值（prevent 模式）自动封禁 IP")
    g.add_argument("--ids-ips-detect-score", dest="IDS_IPS_DETECT_SCORE", type=int, default=None,
                   help="累计风险分超此值（detect 模式）升级告警")
    g.add_argument("--ids-ips-param-flood", dest="IDS_IPS_PARAM_FLOOD", type=int, default=None,
                   help="单请求参数数量上限（超过视为参数洪水）")

    # ---- 上网行为管理 ----
    g = p.add_argument_group("上网行为管理")
    g.add_argument("--web-filter-enabled", action=argparse.BooleanOptionalAction,
                   dest="WEB_FILTER_ENABLED", default=None, help="启用上网行为管理（内容过滤 + 行为审计）")
    g.add_argument("--web-filter-mode", dest="WEB_FILTER_MODE",
                   choices=["monitor", "block"], default=None,
                   help="运行模式：monitor=仅记录，block=拦截违规分类（默认 block）")
    g.add_argument("--web-filter-log-all", action=argparse.BooleanOptionalAction,
                   dest="WEB_FILTER_LOG_ALL", default=None, help="记录所有访问（行为审计留痕）")
    g.add_argument("--web-filter-bypass-admin", action=argparse.BooleanOptionalAction,
                   dest="WEB_FILTER_BYPASS_ADMIN", default=None, help="管理员豁免内容拦截（仍记日志）")
    g.add_argument("--web-filter-block", dest="WEB_FILTER_BLOCK", default=None,
                   help="封禁分类列表（逗号分隔：malware,phishing,gambling,adult,proxy…）")

    # ---- 堡垒机（特权访问管理 PAM） ----
    g = p.add_argument_group("堡垒机（特权访问管理）")
    g.add_argument("--bastion-enabled", action=argparse.BooleanOptionalAction,
                   dest="BASTION_ENABLED", default=None, help="启用堡垒机（特权操作审计记录）")
    g.add_argument("--bastion-record-admin-routes", action=argparse.BooleanOptionalAction,
                   dest="BASTION_RECORD_ADMIN_ROUTES", default=None, help="记录管理路由访问")
    g.add_argument("--bastion-approval-enabled", action=argparse.BooleanOptionalAction,
                   dest="BASTION_APPROVAL_ENABLED", default=None, help="开启高危命令审批工作流")
    g.add_argument("--bastion-risk-commands", dest="BASTION_RISK_COMMANDS", default=None,
                   help="需审批的高危命令（逗号分隔）")

    # ---- 日志审计服务器 ----
    g = p.add_argument_group("日志审计服务器")
    g.add_argument("--audit-enabled", action=argparse.BooleanOptionalAction,
                   dest="AUDIT_ENABLED", default=None, help="启用统一审计收口")
    g.add_argument("--audit-retention-days", dest="AUDIT_RETENTION_DAYS", type=int, default=None,
                   help="审计保留天数（0=永久）")
    g.add_argument("--audit-forward-to-lb", action=argparse.BooleanOptionalAction,
                   dest="AUDIT_FORWARD_TO_LB", default=None, help="集群 Worker 把审计转发给 LB")
    g.add_argument("--audit-syslog-target", dest="AUDIT_SYSLOG_TARGET", default=None,
                   help="审计外发目标（syslog://host:port 或 https://siem...，空=不转发）")

    # ---- 认证服务器 ----
    g = p.add_argument_group("认证服务器")
    g.add_argument("--auth-server-enabled", action=argparse.BooleanOptionalAction,
                   dest="AUTH_SERVER_ENABLED", default=None, help="启用集中式认证/令牌自省")
    g.add_argument("--auth-server-introspection", action=argparse.BooleanOptionalAction,
                   dest="AUTH_SERVER_INTROSPECTION", default=None, help="开放 /api/auth/introspect 自省接口")

    # ---- Console 精细化权限（目标 3.2） ----
    g = p.add_argument_group("Console 精细化权限")
    g.add_argument("--console-max-tier", dest="CONSOLE_MAX_TIER", type=int, default=None,
                   help="主 RCON/Console 密钥授予的最高权限层级 0=info 1=op 2=admin（默认 2）")
    g.add_argument("--console-rcon-default-tier", dest="CONSOLE_RCON_DEFAULT_TIER", type=int,
                   default=None, help="业务 RCON 命令默认层级（默认 1=op）")
    g.add_argument("--console-key-tiers", dest="CONSOLE_KEY_TIERS", default=None,
                   help='受限密钥层级表 JSON，如 \'{"readonly_key": 0}\'')

    # ---- 启动自检 / 接口监控（目标 4.1） ----
    g = p.add_argument_group("启动自检 / 接口监控")
    g.add_argument("--selftest-enabled", action=argparse.BooleanOptionalAction,
                   dest="SELFTEST_ENABLED", default=None, help="启动及手动触发接口自检")
    g.add_argument("--selftest-cache-ttl", dest="SELFTEST_CACHE_TTL", type=int, default=None,
                   help="自检结果缓存秒数（默认 600）")
    g.add_argument("--selftest-blacklist", dest="SELFTEST_BLACKLIST", default=None,
                   help="自检跳过端点前缀（逗号分隔）")
    g.add_argument("--selftest-whitelist", dest="SELFTEST_WHITELIST", default=None,
                   help="自检仅测这些前缀（逗号分隔，空=全部 GET）")

    # ---- SMTP / 邮件 ----
    g = p.add_argument_group("SMTP / 邮件")
    g.add_argument("--smtp-server", dest="SMTP_SERVER", default=None, help="SMTP 服务器")
    g.add_argument("--smtp-port", dest="SMTP_PORT", type=int, default=None, help="SMTP 端口")
    g.add_argument("--smtp-user", dest="SMTP_USER", default=None, help="SMTP 用户名")
    g.add_argument("--smtp-pass", dest="SMTP_PASS", default=None, help="SMTP 密码")
    g.add_argument("--smtp-from", dest="SMTP_FROM", default=None, help="SMTP 发件人名称")

    # ---- RCON 远程控制台 ----
    g = p.add_argument_group("RCON 远程控制台")
    g.add_argument("--rcon-enabled", action=argparse.BooleanOptionalAction, dest="RCON_ENABLED",
                   default=None, help="启用 RCON 远程控制台")
    g.add_argument("--rcon-secret", dest="RCON_SECRET", default=None, help="RCON 共享密钥")
    g.add_argument("--rcon-rsa-key-size", dest="RCON_RSA_KEY_SIZE", type=int, default=None,
                   help="RCON RSA 密钥位数")

    # ---- Cloudflare 真实客户端 IP ----
    g = p.add_argument_group("Cloudflare 真实客户端 IP")
    g.add_argument("--cloudflare-trusted", dest="CLOUDFLARE_TRUSTED",
                   choices=["auto", "true", "false"], default=None,
                   help="是否信任 Cloudflare 真实客户端 IP")
    g.add_argument("--cloudflare-ip-refresh-enabled", action=argparse.BooleanOptionalAction,
                   dest="CLOUDFLARE_IP_REFRESH_ENABLED", default=None, help="定期刷新 Cloudflare IP 段")
    g.add_argument("--cloudflare-ip-refresh-hours", dest="CLOUDFLARE_IP_REFRESH_HOURS",
                   type=float, default=None, help="Cloudflare IP 段刷新间隔（小时）")

    return p


def _print_effective_config() -> None:
    """打印当前生效的配置（密钥脱敏），按字母序。"""
    import json
    _secret_markers = ("SECRET", "PASS", "KEY", "TOKEN")
    _lines = []
    for _name in dir(configs):
        if not _name.isupper() or _name.startswith("_"):
            continue
        _val = getattr(configs, _name)
        if isinstance(_val, (list, tuple)):
            _val_str = ", ".join(str(x) for x in _val)
        elif isinstance(_val, dict):
            _val_str = json.dumps(_val, ensure_ascii=False)
        elif _val is None or isinstance(_val, (str, int, float, bool)):
            _val_str = str(_val)
        else:
            continue
        if any(_m in _name for _m in _secret_markers):
            _val_str = "***"
        _lines.append(f"{_name} = {_val_str}")
    for _line in sorted(_lines):
        print(_line)


def main() -> None:
    # 完整命令行参数解析：覆盖 configs.py 的主要配置项。
    # 未指定 --static-role 时，角色由自适应选举动态获得/转换。
    _parser = _build_arg_parser()
    _ns, _unknown = _parser.parse_known_args()
    if _unknown:
        logger.warning("忽略未知启动参数: %s", " ".join(_unknown))

    # 提前退出的非服务类指令
    if _ns.version:
        print(f"APIProxy {APP_VERSION}")
        return
    if _ns.log_level:
        logging.getLogger().setLevel(getattr(logging, _ns.log_level))

    # 把提供的覆盖项组装成 {配置项名: value}，交给 configs 统一写回并修正派生值
    _overrides = {}
    for _k, _v in vars(_ns).items():
        if _k in ("version", "log_level", "print_config"):
            continue
        if _v is None:
            continue
        _overrides[_k] = _v
    configs.apply_cli_overrides(_overrides)

    if _ns.print_config:
        _print_effective_config()
        return

    preflight_checks()
    harden_file_permissions()
    create_app()
    init_database()
    start_background_services()
    serve_https() if SSL_ENABLED else serve_http()


if __name__ == '__main__':
    main()
