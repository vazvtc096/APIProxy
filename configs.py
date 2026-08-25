# -*- coding: utf-8 -*-
"""配置加载（支持 .json / .yaml(.yml) / .toml，不再使用 .env）。

查找顺序（同目录下，先命中先用）：
    config.toml > config.yaml > config.yml > config.json
也可用环境变量 APIPROXY_CONFIG 指定配置文件绝对路径。

兼容性：
- 仍导出历史扁平变量名（SMTP_SERVER、WAF_ENABLED、BASEURL、APIKEY ...），
  其余模块无需改动 import。
- 新增 UPSTREAMS（多上游 API Key 列表）与 PRICING（按模型 / 时段的计费表）。
- 顶层标量键可用环境变量 APIPROXY_<大写键名> 覆盖（便于在容器里注入密钥）。
"""
from pathlib import Path
import os
import json
import logging

BASE_DIR = Path(__file__).resolve().parent


def _load_raw():
    """按扩展名解析配置文件，返回 (dict, Path|None)。"""
    candidates = []
    env_cfg = os.getenv("APIPROXY_CONFIG")
    if env_cfg:
        candidates.append(Path(env_cfg))
    for name in ("config.toml", "config.yaml", "config.yml", "config.json"):
        candidates.append(BASE_DIR / name)

    for p in candidates:
        if p.exists():
            text = p.read_text(encoding="utf-8")
            suffix = p.suffix.lower()
            try:
                if suffix == ".json":
                    return json.loads(text), p
                if suffix in (".yaml", ".yml"):
                    import yaml  # PyYAML
                    return yaml.safe_load(text) or {}, p
                if suffix == ".toml":
                    import tomllib  # Python 3.11+ 标准库
                    return tomllib.loads(text), p
            except Exception as e:
                logging.critical(f"Failed to parse config file {p}: {e}")
                raise SystemExit(2) from e
    # 没有任何配置文件：回退到全部默认值（下方各 _get 默认值）
    return {}, None


_RAW, _CFG_PATH = _load_raw()
CONFIG_PATH = _CFG_PATH


def _get(key, default=None):
    v = _RAW.get(key, None)
    return v if v is not None else default


def _get_bool(key, default=False):
    v = _RAW.get(key, None)
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _get_int(key, default=0):
    try:
        v = _RAW.get(key, None)
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _env_str(name, key, default=""):
    """优先读裸环境变量，回退到配置文件值。"""
    v = os.getenv(name)
    if v is not None:
        return v
    return _get(key, default)


def _env_bool(name, key, default=False):
    v = os.getenv(name)
    if v is not None:
        return str(v).strip().lower() in ("1", "true", "yes", "on")
    return _get_bool(key, default)


def _env_int(name, key, default=0):
    v = os.getenv(name)
    if v is not None:
        try:
            return int(v)
        except (TypeError, ValueError):
            return default
    return _get_int(key, default)


# 顶层标量键允许用环境变量覆盖（仅字符串/数字/布尔；不覆盖嵌套 upstreams/pricing）
for _k in list(_RAW.keys()):
    if _k in ("upstreams", "pricing"):
        continue
    _env = os.getenv("APIPROXY_" + str(_k).upper())
    if _env is not None:
        _RAW[_k] = _env


# ---------- 基础 ----------
DB_PATH = os.getenv("DB_PATH", _get("DB_PATH", str(BASE_DIR / "users.db")))
# 数据库后端：sqlite（默认）| postgres。DATABASE_URL 仅在 postgres 时使用
#（格式：postgresql://user:pass@host:5432/dbname）
DB_TYPE = os.getenv("DB_TYPE", _get("DB_TYPE", "sqlite")).strip().lower()
DATABASE_URL = os.getenv("DATABASE_URL", _get("DATABASE_URL", "")) or ""
# Redis（可选）：用于限流/缓存加速。未配置则回退 SQLite。
# 格式：redis://[:password@]host:6379/0
REDIS_URL = os.getenv("REDIS_URL", _get("REDIS_URL", "")) or ""

# ---------- 服务绑定（命令行 --host / --port / --debug 可覆盖） ----------
BIND_HOST = os.getenv("BIND_HOST", "0.0.0.0")        # HTTP/HTTPS 监听地址
PORT = int(os.getenv("PORT", "5000"))                # 单机模式 HTTP 端口
DEBUG = os.getenv("DEBUG", "false").strip().lower() == "true"  # 调试模式（生产禁止）

# ---------- 分布式集群（服务发现 + 智能路由） ----------
# 架构：LB（负载均衡器）唯一对外固定端口 + 注册中心（TCP 或组播）；
#       Worker（服务端）注册/上报指标，超时未发现 LB 自动关闭。
# 传输层（CLUSTER_TRANSPORT）：
#   multicast（默认）：UDP 组播，仅限局域网/同网段；
#   tcp：单播注册中心（LB 监听 CLUSTER_TCP_PORT，Worker 主动连 LB），跨网段可用。
CLUSTER_ENABLED = _env_bool("CLUSTER_ENABLED", "CLUSTER_ENABLED", False)
CLUSTER_ROLE = _env_str("CLUSTER_ROLE", "CLUSTER_ROLE", "worker").strip().lower()  # lb | worker
CLUSTER_TRANSPORT = _env_str("CLUSTER_TRANSPORT", "CLUSTER_TRANSPORT", "multicast").strip().lower()  # multicast | tcp
CLUSTER_GROUP = _env_str("CLUSTER_GROUP", "CLUSTER_GROUP", "239.255.0.1")          # 组播地址（multicast）
CLUSTER_PORT = _env_int("CLUSTER_PORT", "CLUSTER_PORT", 5005)                       # 组播端口（multicast）
CLUSTER_TCP_PORT = _env_int("CLUSTER_TCP_PORT", "CLUSTER_TCP_PORT", 5006)          # TCP 注册端口（tcp 模式，LB 监听）
CLUSTER_LB_HOST = _env_str("CLUSTER_LB_HOST", "CLUSTER_LB_HOST", "")               # Worker 连接 LB 的地址（tcp 模式，留空则取本机 IP）
CLUSTER_VNET = _env_bool("CLUSTER_VNET", "CLUSTER_VNET", False)  # 虚拟网络模式（用 VirtualRouter 模拟跨网段，tcp 传输层走 WrappedSocket）
CLUSTER_INTERVAL = _env_int("CLUSTER_INTERVAL", "CLUSTER_INTERVAL", 5)              # 心跳间隔（秒）
CLUSTER_LB_PORT = _env_int("CLUSTER_LB_PORT", "CLUSTER_LB_PORT", 8000)              # LB 对外固定端口
CLUSTER_NODE_PORT = _env_int("CLUSTER_NODE_PORT", "CLUSTER_NODE_PORT", 0)           # Worker 服务端口（0=随机）
CLUSTER_WORKER_TIMEOUT = _env_int("CLUSTER_WORKER_TIMEOUT", "CLUSTER_WORKER_TIMEOUT", 180)  # Worker 超时自杀秒数
CLUSTER_WEIGHTS = {
    "cpu": 0.4, "mem": 0.3, "conn": 0.3,   # 资源占用权重（cpu/mem/连接数）
}
# ---------- 自适应模式（服务注册中心自动选举 LB/Worker） ----------
# CLUSTER_MODE = auto（默认）| lb | worker
#   auto  ：启动时自动探测并选举角色（统一服务注册中心，零配置自组织）
#   lb / worker：沿用旧静态角色（兼容显式指定 CLUSTER_ROLE 的部署）
# 兼容逻辑：若显式设置了 CLUSTER_ROLE=lb|worker 而未设置 CLUSTER_MODE，则沿用该角色。
_CLUSTER_MODE_ENV = os.getenv("CLUSTER_MODE")
_CLUSTER_MODE_RAW = _RAW.get("CLUSTER_MODE")
if _CLUSTER_MODE_ENV:
    CLUSTER_MODE = _CLUSTER_MODE_ENV.strip().lower()
elif _CLUSTER_MODE_RAW is not None:
    CLUSTER_MODE = str(_CLUSTER_MODE_RAW).strip().lower()
elif _RAW.get("CLUSTER_ROLE") is not None or os.getenv("CLUSTER_ROLE"):
    CLUSTER_MODE = str(_RAW.get("CLUSTER_ROLE") or os.getenv("CLUSTER_ROLE")).strip().lower()
else:
    CLUSTER_MODE = "auto"
CLUSTER_BOOTSTRAP_WAIT = _env_int("CLUSTER_BOOTSTRAP_WAIT", "CLUSTER_BOOTSTRAP_WAIT", 3)  # 选举/发现窗口（秒）
CLUSTER_STATIC_ROLE = None  # 由启动参数 --static-role 注入；None=动态选举，{worker,lb}=强制指定
CLUSTER_SECRET = _env_str("CLUSTER_SECRET", "CLUSTER_SECRET", "")  # 集群节点间消息鉴权共享密钥（空=不鉴权，仅限可信内网）
BASEURL = _get("baseurl", "") or ""
APIKEY = _get("apikey", "") or ""

SESSION_SECRET = _get("SESSION_SECRET", "") or ""
TOKEN_SECRET = _get("TOKEN_SECRET", "") or ""
OAUTH_JWT_SECRET = _get("OAUTH_JWT_SECRET", "") or ""
OAUTH_REGISTRATION_OPEN = _get_bool("OAUTH_REGISTRATION_OPEN", True)

# ---------- SMTP ----------
SMTP_SERVER = _get("SMTP_SERVER", "smtp.163.com")
SMTP_PORT = _get_int("SMTP_PORT", 465)
SMTP_USER = _get("SMTP_USER", "") or ""
SMTP_PASS = _get("SMTP_PASS", "") or ""
SMTP_FROM = _get("SMTP_FROM", "Cloud LLM API 代理")
# SMTP 是否已配置（用户名 + 密码均非空才视为可用）
SMTP_CONFIGURED = bool(SMTP_USER and SMTP_PASS)

# ---------- RCON 远程控制台 ----------
RCON_ENABLED = _get_bool("RCON_ENABLED", True)
RCON_SECRET = _get("RCON_SECRET", "") or ""
RCON_RSA_KEY_SIZE = _get_int("RCON_RSA_KEY_SIZE", 2048)

# ---------- Console 运维控制台（取代 RCON 的游戏化命名）----------
# 复用 RCON 的开关与密钥：CONSOLE 是 RCON 的运维面重命名，鉴权共用一把最高权限密钥。
CONSOLE_ENABLED = RCON_ENABLED
CONSOLE_SECRET = RCON_SECRET

# ---------- HTTPS/SSL ----------
SSL_ENABLED = _get_bool("SSL_ENABLED", False)
SSL_CERT = _get("SSL_CERT", "") or ""
SSL_KEY = _get("SSL_KEY", "") or ""
HTTPS_PORT = _get_int("HTTPS_PORT", 5443)

# ---------- WAF（Web 应用防火墙）与行为监测 ----------
WAF_ENABLED = _get_bool("WAF_ENABLED", True)
WAF_DISABLE_IF_CLOUDFLARE = _get_bool("WAF_DISABLE_IF_CLOUDFLARE", True)
WAF_MAX_BODY_BYTES = _get_int("WAF_MAX_BODY_BYTES", 1048576)
_WAF_ALLOWED_HOSTS_RAW = _get("WAF_ALLOWED_HOSTS", "") or ""
if isinstance(_WAF_ALLOWED_HOSTS_RAW, list):
    WAF_ALLOWED_HOSTS = [str(h).strip() for h in _WAF_ALLOWED_HOSTS_RAW if str(h).strip()]
else:
    WAF_ALLOWED_HOSTS = [h.strip() for h in str(_WAF_ALLOWED_HOSTS_RAW).split(",") if h.strip()]
WAF_GLOBAL_RPM = _get_int("WAF_GLOBAL_RPM", 180)
WAF_VIOLATIONS_RPM = _get_int("WAF_VIOLATIONS_RPM", 10)
WAF_BAN_MINUTES = _get_int("WAF_BAN_MINUTES", 60)

# ---------- IDS / IPS（入侵检测与防御系统）----------
# 与 WAF 互补：WAF 管 Web 应用层攻击，IDS/IPS 管入侵行为层面
# （漏洞利用载荷、端点扫描、认证暴破等）。详见 ids_ips.py。
IDS_IPS_ENABLED = _get_bool("IDS_IPS_ENABLED", True)        # 总开关（默认开启）
IDS_IPS_MODE = _get("IDS_IPS_MODE", "prevent")             # detect=仅告警 | prevent=拦截+自动封禁
IDS_IPS_BAN_ON_CRITICAL = _get_bool("IDS_IPS_BAN_ON_CRITICAL", True)  # 命中严重签名即封禁 IP
IDS_IPS_BAN_MINUTES = _get_int("IDS_IPS_BAN_MINUTES", 60)  # 自动封禁时长（分钟）
IDS_IPS_SCAN_PATHS = _get_int("IDS_IPS_SCAN_PATHS", 15)    # 端点扫描：窗口内不同 404 路径阈值
IDS_IPS_SCAN_WINDOW = _get_int("IDS_IPS_SCAN_WINDOW", 60)  # 端点扫描窗口（秒）
IDS_IPS_AUTHFAIL_THRESHOLD = _get_int("IDS_IPS_AUTHFAIL_THRESHOLD", 20)  # 暴破：窗口内 401/403 次数阈值
IDS_IPS_AUTHFAIL_WINDOW = _get_int("IDS_IPS_AUTHFAIL_WINDOW", 300)       # 暴破窗口（秒）
IDS_IPS_BLOCK_SCORE = _get_int("IDS_IPS_BLOCK_SCORE", 100)  # 累计风险分超此值（prevent）自动封禁
IDS_IPS_DETECT_SCORE = _get_int("IDS_IPS_DETECT_SCORE", 40) # 累计风险分超此值（detect）升级告警
IDS_IPS_PARAM_FLOOD = _get_int("IDS_IPS_PARAM_FLOOD", 200)  # 单请求参数数量上限

# ---------- 上网行为管理（Web 行为过滤 + 全站上网行为审计）----------
# 与 WAF/IDS 互补：WAF 管攻击、IDS 管入侵，本模块管「员工/用户上网内容合规」。
# 详见 web_filter.py。
WEB_FILTER_ENABLED = _get_bool("WEB_FILTER_ENABLED", True)       # 总开关（默认开启）
WEB_FILTER_MODE = _get("WEB_FILTER_MODE", "block")             # monitor=仅记录 | block=拦截违规分类
WEB_FILTER_LOG_ALL = _get_bool("WEB_FILTER_LOG_ALL", True)     # 是否记录所有访问（行为审计留痕）
WEB_FILTER_BYPASS_ADMIN = _get_bool("WEB_FILTER_BYPASS_ADMIN", True)  # 管理员豁免内容过滤（仍记日志）
# 默认封禁分类（逗号分隔）：恶意/钓鱼/赌博/成人/代理匿名
_WEB_FILTER_BLOCK_RAW = _get("WEB_FILTER_BLOCK", "malware,phishing,gambling,adult,proxy")
if isinstance(_WEB_FILTER_BLOCK_RAW, list):
    WEB_FILTER_BLOCK = [str(c).strip().lower() for c in _WEB_FILTER_BLOCK_RAW if str(c).strip()]
else:
    WEB_FILTER_BLOCK = [c.strip().lower() for c in str(_WEB_FILTER_BLOCK_RAW).split(",") if c.strip()]

# ---------- 堡垒机（特权访问管理 PAM，可选）----------
# 记录所有特权操作（Console 运维命令 + 管理路由访问），可开启高危命令审批工作流。
# 详见 bastion.py。
BASTION_ENABLED = _get_bool("BASTION_ENABLED", True)            # 总开关（默认开启，仅记录）
BASTION_RECORD_ADMIN_ROUTES = _get_bool("BASTION_RECORD_ADMIN_ROUTES", True)  # 记录管理路由访问
BASTION_APPROVAL_ENABLED = _get_bool("BASTION_APPROVAL_ENABLED", False)  # 高危命令审批（默认关，避免阻断运维）
_BASTION_RISK_RAW = _get("BASTION_RISK_COMMANDS",
                         "ban_ip,unban_ip,ids_block,ids_unblock,maintenance_on,drain,resume,flush_cache,ban_account,unban_account")
if isinstance(_BASTION_RISK_RAW, list):
    BASTION_RISK_COMMANDS = [str(c).strip().lower() for c in _BASTION_RISK_RAW if str(c).strip()]
else:
    BASTION_RISK_COMMANDS = [c.strip().lower() for c in str(_BASTION_RISK_RAW).split(",") if c.strip()]

# ---------- 日志审计服务器（统一审计 + 查询/导出）----------
# 作为全站审计的「统一收口」：安全/WAF/IDS、上网行为、堡垒机、认证事件写入 audit_log，
# 提供统一查询/导出，并支持集群内 Worker→LB 转发与可选 syslog/SIEM 外发。
# 详见 audit_server.py。
AUDIT_ENABLED = _get_bool("AUDIT_ENABLED", True)                # 总开关（默认开启）
AUDIT_RETENTION_DAYS = _get_int("AUDIT_RETENTION_DAYS", 90)    # 审计保留天数（0=永久）
AUDIT_FORWARD_TO_LB = _get_bool("AUDIT_FORWARD_TO_LB", False)  # 集群 Worker 是否把审计转发给 LB
AUDIT_SYSLOG_TARGET = _get("AUDIT_SYSLOG_TARGET", "") or ""    # 可选外发目标：syslog://host:port 或 https://siem...（空=不转发）

# ---------- 认证服务器（集中式认证 / 令牌自省）----------
# 复用 core_session/core_auth：对外提供令牌自省、会话校验、吊销接口；集群模式下
# Worker 可委托 LB 的认证服务器校验会话，避免各自依赖本地库。详见 auth_server.py。
AUTH_SERVER_ENABLED = _get_bool("AUTH_SERVER_ENABLED", True)
AUTH_SERVER_INTROSPECTION = _get_bool("AUTH_SERVER_INTROSPECTION", True)  # 是否开放 /api/auth/introspect

# 公告是否仍额外投递到「admin 好友」聊天会话（旧行为）。
# True = 兼容旧版（用户在「消息」里也能看到公告）；False = 仅投递到通知铃铛，
# admin 不再作为虚拟好友出现在聊天列表里。
ANNOUNCEMENT_DELIVER_TO_CHAT = _get_bool("ANNOUNCEMENT_DELIVER_TO_CHAT", True)

# ---------- Console 精细化权限（目标 3.2）----------
# 命令分 3 个权限层级（数值越大权限越高）：
#   0 = info  只读 / 查询（status / list / query 类）
#   1 = op    非破坏性运维（reload / loglevel / unban / announce ...）
#   2 = admin 高危 / 破坏性（ban / flush_cache / maintenance_on / drain ...）
CONSOLE_MAX_TIER = _get_int("CONSOLE_MAX_TIER", 2)   # 主 RCON/Console 密钥授予的最高层级（默认 admin 全权）
CONSOLE_RCON_DEFAULT_TIER = _get_int("CONSOLE_RCON_DEFAULT_TIER", 1)  # 业务 RCON 命令默认层级
# 可选：为额外「受限密钥」指定更低层级，格式 JSON：{"<key>": <tier>}
# 例如只给监控账号一把 tier=0 的密钥，仅能跑只读查询。
_CONSOLE_KEY_TIERS_RAW = _get("CONSOLE_KEY_TIERS", "") or ""
try:
    if isinstance(_CONSOLE_KEY_TIERS_RAW, dict):
        CONSOLE_KEY_TIERS = {str(k): int(v) for k, v in _CONSOLE_KEY_TIERS_RAW.items()}
    elif _CONSOLE_KEY_TIERS_RAW:
        CONSOLE_KEY_TIERS = {str(k): int(v) for k, v in json.loads(_CONSOLE_KEY_TIERS_RAW).items()}
    else:
        CONSOLE_KEY_TIERS = {}
except Exception:
    CONSOLE_KEY_TIERS = {}

# ---------- 启动自检 / 接口监控（目标 4.1）----------
# 每次启动（以及可经 Console `selftest` 手动触发）对全部 GET 路由做冒烟探测，
# 结果写入统一缓存（默认 10 分钟 TTL），供 /api/health/* 与页面不稳定提示使用。
SELFTEST_ENABLED = _get_bool("SELFTEST_ENABLED", True)
SELFTEST_CACHE_TTL = _get_int("SELFTEST_CACHE_TTL", 600)        # 结果缓存秒数（10 分钟）
SELFTEST_BLACKLIST = _get("SELFTEST_BLACKLIST", "") or ""       # 逗号分隔前缀，跳过这些端点
SELFTEST_WHITELIST = _get("SELFTEST_WHITELIST", "") or ""       # 逗号分隔前缀，仅测这些（空=全部 GET）

# ---------- Cloudflare 真实客户端 IP ----------
_CFT = str(_get("CLOUDFLARE_TRUSTED", "auto")).strip().strip('"').strip("'").lower()
CLOUDFLARE_TRUSTED = _CFT if _CFT in ("auto", "true", "false") else "auto"
CLOUDFLARE_IP_REFRESH_ENABLED = _get_bool("CLOUDFLARE_IP_REFRESH_ENABLED", True)
try:
    CLOUDFLARE_IP_REFRESH_HOURS = float(_get("CLOUDFLARE_IP_REFRESH_HOURS", 24))
except (TypeError, ValueError):
    CLOUDFLARE_IP_REFRESH_HOURS = 24.0


# ---------- 多上游 API Key（自定义名称 / 优先级 / 禁用模型） ----------
def _resolve_upstream_api_key(name: str, configured_key: str) -> str:
    """解析上游 API Key：配置文件中有值则用配置值，否则从环境变量注入。

    环境变量命名规则：APIPROXY_UPSTREAM_<NAME>_API_KEY
    其中 <NAME> 为上游名称的 大写 + 下划线 转换（如 deepseek-main → DEEPSEEK_MAIN）。
    """
    if configured_key:
        return configured_key
    env_var = "APIPROXY_UPSTREAM_" + name.upper().replace("-", "_") + "_API_KEY"
    return os.getenv(env_var, "") or ""


def _normalize_upstreams(raw):
    """把配置中的 upstreams 规整为统一结构列表。"""
    ups = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            ups.append({
                "name": name,
                "base_url": str(item.get("base_url") or BASEURL or "").strip(),
                "api_key": _resolve_upstream_api_key(name, str(item.get("api_key") or "").strip()),
                "priority": int(item.get("priority", 100)),
                "enabled": bool(item.get("enabled", True)),
                "disabled_models": [str(m).strip() for m in (item.get("disabled_models") or []) if str(m).strip()],
            })
    # 若未配置任何 upstreams，用顶层 baseurl/apikey 兜底成单上游
    if not ups:
        if BASEURL or APIKEY:
            ups.append({
                "name": "default",
                "base_url": BASEURL,
                "api_key": APIKEY,
                "priority": 1,
                "enabled": True,
                "disabled_models": [],
            })
    return ups


UPSTREAMS = _normalize_upstreams(_RAW.get("upstreams"))
# 始终保证 BASEURL/APIKEY 指向第一个可用上游（兼容 api_caller 等旧代码）
if UPSTREAMS:
    BASEURL = BASEURL or UPSTREAMS[0]["base_url"]
    APIKEY = APIKEY or UPSTREAMS[0]["api_key"]

# ---------- 计费表（按模型 / 时段；可选 model@upstream 绑定） ----------
PRICING = _RAW.get("pricing", {}) or {}


# ---------- 启动时密钥检查 ----------
def check_secrets() -> list[str]:
    """检查敏感密钥配置状态，返回缺失项的警告消息列表。"""
    warnings = []
    # 上游 API key 不在配置文件中检查：上游需运行时动态扩展，由 DB
    # （upstreams.reload_upstreams_from_db）管理，启动时 startup_refresh()
    # 会实际拉取模型目录验证可用性；config.yaml 仅作为 DB 为空时的种子。
    if not OAUTH_JWT_SECRET:
        warnings.append(
            "OAUTH_JWT_SECRET is empty. OAuth token signing is disabled (fail-closed). "
            "Set it via config.yaml or env var APIPROXY_OAUTH_JWT_SECRET."
        )
    if not SMTP_CONFIGURED:
        warnings.append(
            "SMTP not configured (SMTP_USER/SMTP_PASS empty). "
            "Email verification and password reset will be unavailable."
        )
    return warnings


# ---------- 命令行覆盖 ----------
def apply_cli_overrides(overrides: dict) -> None:
    """把命令行覆盖项写回本模块，并修正受影响的派生值。

    overrides: {配置项名(大写, 如 'CLUSTER_ENABLED'): value}
    仅处理 value 非 None 的项；布尔项来自 argparse.BooleanOptionalAction，
    已是 bool，直接写入即可。调用时机：configs 已导入、各模块尚未读取前
    （即在 __main__.main() 的 preflight_checks() 之前）。
    """
    g = globals()
    provided = set()
    for k, v in overrides.items():
        if v is None:
            continue
        g[k] = v
        provided.add(k)

    # 派生值修正
    if provided & {"SMTP_USER", "SMTP_PASS"}:
        g["SMTP_CONFIGURED"] = bool(g.get("SMTP_USER") and g.get("SMTP_PASS"))

    if "WAF_ALLOWED_HOSTS" in provided:
        raw = g["WAF_ALLOWED_HOSTS"]
        if isinstance(raw, (list, tuple)):
            g["WAF_ALLOWED_HOSTS"] = [str(h).strip() for h in raw if str(h).strip()]
        else:
            g["WAF_ALLOWED_HOSTS"] = [h.strip() for h in str(raw).split(",") if h.strip()]

    if "CLOUDFLARE_TRUSTED" in provided:
        cft = str(g["CLOUDFLARE_TRUSTED"]).strip().lower()
        g["CLOUDFLARE_TRUSTED"] = cft if cft in ("auto", "true", "false") else "auto"

    # 列表型字段（逗号分隔字符串 → list）
    for _lst_key in ("WEB_FILTER_BLOCK", "BASTION_RISK_COMMANDS",
                     "SELFTEST_BLACKLIST", "SELFTEST_WHITELIST"):
        if _lst_key in provided:
            raw = g[_lst_key]
            if isinstance(raw, (list, tuple)):
                g[_lst_key] = [str(x).strip() for x in raw if str(x).strip()]
            else:
                g[_lst_key] = [x.strip() for x in str(raw).split(",") if x.strip()]

    # Console 受限密钥表（JSON 字符串 → dict）
    if "CONSOLE_KEY_TIERS" in provided:
        raw = g["CONSOLE_KEY_TIERS"]
        try:
            _parsed = json.loads(raw) if isinstance(raw, str) else raw
            g["CONSOLE_KEY_TIERS"] = {str(k): int(v) for k, v in _parsed.items()}
        except Exception:
            logger.warning("无法解析 CONSOLE_KEY_TIERS，忽略：%r", raw)
            g["CONSOLE_KEY_TIERS"] = {}

    # 角色 / 模式解析（与模块加载逻辑保持一致）
    if "CLUSTER_MODE" in provided:
        g["CLUSTER_MODE"] = str(g["CLUSTER_MODE"]).strip().lower()
    elif "CLUSTER_ROLE" in provided:
        g["CLUSTER_MODE"] = str(g["CLUSTER_ROLE"]).strip().lower()

    # 上游兜底（--baseurl / --apikey）：仅当配置文件中无 upstreams 时，
    # 用覆盖后的 BASEURL/APIKEY 重建默认单上游，使兜底生效。
    if provided & {"BASEURL", "APIKEY"} and not _RAW.get("upstreams"):
        g["UPSTREAMS"] = _normalize_upstreams(None)


if __name__ == "__main__":
    print(f"Config file : {CONFIG_PATH}")
    print(f"Upstreams   : {[ (u['name'], u['priority'], u['enabled']) for u in UPSTREAMS ]}")
    print(f"SMTP_CONFIGURED: {SMTP_CONFIGURED}")
    print(f"Pricing models  : {list((PRICING.get('models') or {}).keys())}")
    for w in check_secrets():
        print(f"  WARNING: {w}")
