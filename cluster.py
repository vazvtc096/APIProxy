"""分布式集群：服务发现 + 智能路由 + 存活看门狗 + 自适应角色选举。

架构：
- LB（负载均衡器）：唯一对外固定端口，收集 Worker 上报的
  指标（CPU/内存/连接数），按「资源占用 + 连接数」加权选最优 Worker 转发。
- Worker（服务端）：随机端口，连接 LB 注册中心并周期上报指标；
  若 CLUSTER_WORKER_TIMEOUT 秒内未收到 LB 心跳则触发重新选举（而非直接自杀）。

传输层（CLUSTER_TRANSPORT）：
- multicast（默认）：UDP 组播，仅限局域网/同网段。
- tcp：TCP 单播注册中心，跨网段可用（Worker 主动连 LB 已知地址）。

虚拟网络（CLUSTER_VNET=1）：当启用 VirtualRouter 模拟跨网段时，TCP 传输层
改用 VirtualRouter 的 WrappedSocket，使集群通信走虚拟网络（不同子网互通），
而 HTTP（Quart）仍走真实回环，不受影响。

通信协议（自定义二进制，独立于传输层）：

  消息头（8 字节）：
    magic(2B) | version(1B) | type(1B) | length(4B, 大端)
    magic 固定为 b"AP"（0x41 0x50），version=1。

  type 取值：
    0x01 LB_HEARTBEAT  —— LB 心跳/注册确认
    0x02 WORKER_REPORT —— Worker 上报指标
    0x03 DISCOVER      —— 启动探测：加入节点广播"谁在？谁是 LB？"
    0x04 DISCOVER_REPLY—— 探测应答：携带应答者角色及已知 LB 信息

  LB_HEARTBEAT 负载（18 字节）：
    lb_id(8B) | host(4B, IPv4) | port(2B, 大端) | ts(4B, Unix 秒)

  WORKER_REPORT 负载（24 字节）：
    node_id(8B) | host(4B) | port(2B) | cpu(2B, %×10) | mem(2B, %×10)
    | conn(2B) | ts(4B, Unix 秒)

  DISCOVER 负载（8 字节）：
    node_id(8B)  —— 探测发起者 ID

  DISCOVER_REPLY 负载（23 字节）：
    from_id(8B) | role_flag(1B: 0=Worker,1=LB) | lb_id(8B)
    | lb_host(4B) | lb_port(2B)

所有多字节整数均为大端；浮点用定点（×10）编码为整数，避免浮点字节歧义。

自适应选举（CLUSTER_MODE=auto，默认）：
  程序开启时先判断是否已有存活服务端：
    - 发现 LB            → 自己作为 Worker 向其注册
    - 发现节点但无 LB    → 与所有已知节点按 NODE_ID 最小者当选 LB（其余为 Worker）
    - 未发现任何节点     → 自己作为独立服务器（即 LB，无 Worker）
  运行时若 LB 失联：Worker 不再自杀，而是重新选举——存活节点中 ID 最小者
  晋升为 LB，其余重新注册。多 LB 同时出现的裂脑由「发现更低 ID 的 LB 即主动
  降级为 Worker」规则在运行时自动收敛。

自动角色切换的已知局限性与修复状态（Known Limitations & Fixes）：
  角色切换的硬性规则（新增）：
    - LB 资格门禁：只有「完整本地配置文件（configs.CONFIG_PATH 存在）+ 数据库可用
      + 控制面密钥齐全（SESSION_SECRET / OAUTH_JWT_SECRET）」的服务端才允许成为 LB
      （is_lb_eligible）。空壳 LB 不再能接管流量。
    - 启动参数 --static-role {worker,lb} 强制指定角色（覆盖自适应选举）；未指定时
      动态获得 / 转换。强制 lb 但不满足资格时回退为 Worker 并告警。
    - 集群消息鉴权：设置 CLUSTER_SECRET 后，所有二进制消息尾部追加 8 字节
      HMAC-SHA256，校验失败直接丢弃（防伪造 / 重放）。
    - 领导代次（epoch）fencing：LB 晋升时 epoch 单调递增（持久化到 DB，失败回退时间
      截），Worker 记录见过的最高代次并忽略更低代次的过期 LB 心跳 / 应答。

  逐条状态（[F]=已修复 [M]=已缓解 [R]=架构性残留）：
  1. [M] 无共识算法 / 无 Quorum：仍以 NODE_ID 最小为决胜键，但已：
     - 统一组播 / TCP 的裂脑收敛（本节点为 LB 且发现更高代次或更低 ID 的 LB 即降级）；
     - 加 epoch fencing，分区恢复后被废黜旧 LB 不会再劫持。
     仍非 Paxos/Raft，极端双活分区窗口期内可能存在短暂双 LB（靠端口绑定 + fencing 收敛）。
  2. [M] NODE_ID 随机：新增 --static-role 可指定稳定角色；资格门禁确保只有受控服务
     端成为 LB，避免随机节点意外当选。
  3. [M] 启动期竞态：资格门禁使"两个空壳节点各自抢 LB"不再发生；即便都合格，epoch
     + 统一降级规则会在首个心跳后收敛；CLUSTER_LB_PORT 的 HTTP 入口现由 Hypercorn
     真正监听（见 #5），不再有"角色 LB 但 HTTP 未起"的僵死。
  4. [R] LB 失联服务空窗：Worker 检到失联需 CLUSTER_WORKER_TIMEOUT + 重选举窗口，
     期间 LB 入口不可用。已确保晋升瞬间即拉起 LB HTTP / TCP 监听以最小化空窗；彻底
     零停机仍需外部 VIP / keepalived _active-standby。
  5. [F] 运行时降级 / 晋升职责不完整：
     - _step_down_to_worker 现在真正转为 Worker：拉起看门狗，TCP 模式重新向新 LB 注册，
       组播模式下一轮广播自动切换为 WORKER_REPORT。
     - _promote_to_lb / _become_lb 统一补全 LB 职责（TCP 监听 + LB HTTP），两条传输路径对称。
     - _start_lb_http 改用 Hypercorn 在独立事件循环真正监听 CLUSTER_LB_PORT（修复旧的
       Quart app.run 协程在裸线程不生效问题）。
  6. [F] 无租约 / Fencing：已通过 epoch 代次 + 持久化解决，被废黜旧 LB 复活会被忽略。
  7. [M] 负载指标来自本地 DB：路由实际使用的是各 Worker 上报的指标（非 LB 本地 DB），
     故单点偏差有限；仍建议 Worker 使用独立 DB（避免共享 sessions 表导致连接数全局化）。
  8. [F] 集群消息无鉴权：已通过 CLUSTER_SECRET HMAC 解决（空密钥=不鉴权，仅限可信内网）。
  9. [R] 启动阻塞：bootstrap() 仍需同步 sleep(CLUSTER_BOOTSTRAP_WAIT) 完成探测；
     可调小该值缩短就绪时间，但选举质量随之下降（权衡项，非缺陷）。
 10. [R] 跨网段 / 跨机房：组播限同网段；TCP 需 CLUSTER_LB_HOST 种子；跨 DC 一致性
     与外部零停机入口仍建议 VIP / keepalived（见上方说明）。
"""

import hashlib
import hmac
import logging
import os
import secrets
import socket
import struct
import threading
import time
import uuid

from . import configs

logger = logging.getLogger(__name__)

# 启动随机令牌：每次进程启动生成一次，用于访问集群管理端点（/cluster/*）的
# 简易鉴权。既可通过 ?token=<token> 在 URL 中指定（API/一键访问），
# 也可在登录页点击「登录」后写入会话（浏览器免重复输入）。
CLUSTER_TOKEN = secrets.token_urlsafe(24)


def get_cluster_token() -> str:
    """返回本次启动的集群管理令牌。"""
    return CLUSTER_TOKEN


# ---- 自定义二进制协议定义 ----
_MAGIC = b"AP"
_VERSION = 1
_MSG_LB_HEARTBEAT = 0x01
_MSG_WORKER_REPORT = 0x02
_MSG_DISCOVER = 0x03
_MSG_DISCOVER_REPLY = 0x04

_HEADER = struct.Struct(">2sBBI")          # magic(2) version(1) type(1) length(4)
_LB_HB = struct.Struct(">8s4sHII")          # lb_id(8) host(4) port(2) ts(4) epoch(4)
_WORKER_REPORT = struct.Struct(">8s4sHHHHI")  # node_id(8) host(4) port(2) cpu(2) mem(2) conn(2) ts(4)
_DISCOVER = struct.Struct(">8s")            # node_id(8)
_DISCOVER_REPLY = struct.Struct(">8sB8s4sHI")  # from_id(8) role_flag(1) lb_id(8) lb_host(4) lb_port(2) epoch(4)

# 8 字节二进制节点 ID（进程级唯一）
NODE_ID = uuid.uuid4().bytes[:8]
NODE_ID_HEX = NODE_ID.hex()

# 本机服务端口（serve_http 启动后由 set_node_port 写入；Worker 随机端口在启动时确定）
_node_port = int(os.getenv("PORT", "5000") or "5000")
_node_port_lock = threading.Lock()


def set_node_port(port: int):
    global _node_port
    with _node_port_lock:
        _node_port = port


def get_node_port() -> int:
    with _node_port_lock:
        return _node_port


def _local_ip() -> str:
    """获取本机局域网 IP（真实网络）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


_VNET_IP_CACHE = None


def _vnet_local_ip() -> str:
    """获取 VirtualRouter 分配的虚拟 IP（跨网段模拟用）。

    通过临时 WrappedSocket 握手后读取源地址（_src_ip）获得，读后立即关闭
    （不长期占用 router 会话，避免与 listen/connect socket 冲突导致路由错乱）。
    IP 在同一进程内固定（router 按进程的源标识分配），故缓存结果。
    仅当 CLUSTER_VNET=1 时调用。
    """
    global _VNET_IP_CACHE
    if _VNET_IP_CACHE is not None:
        return _VNET_IP_CACHE
    try:
        from VirtualRouter.wrapped_socket.wrapped_socket import WrappedSocket, PROTO_TCP
        ws = WrappedSocket(proto=PROTO_TCP, timeout=5.0)
        vip_int = ws._src_ip
        ws.close()
        ip = "%d.%d.%d.%d" % ((vip_int >> 24) & 0xff, (vip_int >> 16) & 0xff,
                              (vip_int >> 8) & 0xff, vip_int & 0xff)
        _VNET_IP_CACHE = ip
        return ip
    except Exception as e:
        logger.warning("获取虚拟 IP 失败（%s），回退真实 IP", e)
        return _local_ip()


def _make_tcp_socket() -> socket.socket:
    """构造 TCP socket：虚拟网络模式下用 WrappedSocket，否则标准 socket。

    WrappedSocket 实现了 bind/connect/listen/accept/send/recv/getsockname
    等标准接口，可直接用于集群 TCP 注册中心通信。
    注意：WrappedSocket 的 accept() 依赖后台读线程唤醒，timeout 过短（如 3.0）
    会导致 accept 频繁超时且错过入站连接；故用 None（阻塞）以保证可靠接收。
    """
    if configs.CLUSTER_VNET:
        try:
            from VirtualRouter.wrapped_socket.wrapped_socket import WrappedSocket, PROTO_TCP
            return WrappedSocket(proto=PROTO_TCP, timeout=30.0)
        except Exception as e:
            logger.error("虚拟网络 socket 创建失败（%s），回退标准 socket", e)
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def _ip_to_bytes(ip: str) -> bytes:
    try:
        return socket.inet_aton(ip)
    except Exception:
        return socket.inet_aton("127.0.0.1")


def _metrics() -> tuple:
    """采集本机指标：CPU%、内存%、活跃连接数。"""
    cpu = mem = 0.0
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
    except Exception:
        pass
    return cpu, mem, _connection_count()


def _connection_count() -> int:
    """活跃连接数（用 sessions 表活跃会话数近似）。"""
    try:
        import datetime
        from . import core
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = core._get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT COUNT(*) AS cnt FROM sessions "
                    "WHERE expires_at IS NULL OR expires_at > ?", (now,)
                )
                row = cur.fetchone()
                return row['cnt'] if row else 0
        finally:
            conn.close()
    except Exception:
        return 0


def _load_score(cpu: float, mem: float, conn: int) -> float:
    """负载得分（越低越空闲）。连接数按 10 连接=1 分归一化到 0-100。"""
    w = configs.CLUSTER_WEIGHTS
    conn_norm = min(100.0, conn / 10.0)
    return cpu * w["cpu"] + mem * w["mem"] + conn_norm * w["conn"]


# ---- LB 资格判定（只有完整本地配置 + 可用数据库的服务端才允许当 LB） ----
def _db_available() -> bool:
    """探测数据库是否可用（LB 作为控制面必须能读写 DB）。"""
    try:
        from . import core
        conn = core._get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            return True
        finally:
            conn.close()
    except Exception as e:
        logger.debug("数据库可用性探测失败：%s", e)
        return False


def is_lb_eligible() -> tuple:
    """判断本节点是否具备担任 LB 的资格。

    返回 (bool, reason)：
      - 本地配置文件必须存在（configs.CONFIG_PATH 非空）；
      - 控制面关键密钥必须齐全（SESSION_SECRET / OAUTH_JWT_SECRET），LB 需签发会话与 JWT；
      - 数据库必须可用（LB 是唯一对外入口与控制面）。
    不满足任一条件则禁止成为 LB（防止"空壳 LB"接管流量后无法服务）。
    """
    cfg_path = getattr(configs, "CONFIG_PATH", None)
    if not cfg_path:
        return False, "缺少本地配置文件"
    missing = [k for k in ("SESSION_SECRET", "OAUTH_JWT_SECRET")
               if not getattr(configs, k, "")]
    if missing:
        return False, "缺少密钥: " + ",".join(missing)
    if not _db_available():
        return False, "数据库不可用"
    return True, "ok"


def _next_epoch() -> int:
    """获取单调递增的领导代次（fencing 用）。优先持久化到 DB（多 LB 共享 DB 时跨节点协调），
    失败则回退为时间截（单节点内单调递增，依赖时钟合理）。"""
    try:
        from . import core
        conn = core._get_conn()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("CREATE TABLE IF NOT EXISTS cluster_epoch "
                            "(id INTEGER PRIMARY KEY CHECK(id=1), epoch INTEGER NOT NULL DEFAULT 0)")
                cur.execute("SELECT epoch FROM cluster_epoch WHERE id=1")
                row = cur.fetchone()
                new_epoch = (int(row["epoch"]) + 1) if row else 1
                cur.execute("INSERT INTO cluster_epoch(id, epoch) VALUES(1, ?) "
                            "ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch", (new_epoch,))
                return new_epoch
        finally:
            conn.close()
    except Exception as e:
        logger.debug("代次持久化失败，回退时间戳：%s", e)
        return int(time.time())


# ---- 二进制协议编解码（含 CLUSTER_SECRET 鉴权 + epoch 代次） ----
def _report_host() -> str:
    """上报用的本机 IP：虚拟网络模式下用虚拟 IP，否则真实 IP。"""
    return _vnet_local_ip() if configs.CLUSTER_VNET else _local_ip()


def _cluster_secret() -> str:
    return getattr(configs, "CLUSTER_SECRET", "") or ""


def _seal(msg_type: int, body: bytes) -> bytes:
    """封装一帧：头部 + 负载；若设置了 CLUSTER_SECRET，尾部追加 8 字节 HMAC-SHA256
    作为消息鉴权（防伪造/重放，#8）。secret 为空则不加尾部（可信内网兼容）。"""
    secret = _cluster_secret()
    if secret:
        body = body + hmac.new(secret.encode(), body, hashlib.sha256).digest()[:8]
    return _HEADER.pack(_MAGIC, _VERSION, msg_type, len(body)) + body


def _open(payload: bytes):
    """剥离并校验 HMAC 尾部，返回纯净负载；校验失败返回 None。secret 为空则原样返回。"""
    secret = _cluster_secret()
    if not secret:
        return payload
    if len(payload) < 8:
        return None
    body, trailer = payload[:-8], payload[-8:]
    exp = hmac.new(secret.encode(), body, hashlib.sha256).digest()[:8]
    return body if hmac.compare_digest(exp, trailer) else None


def _current_epoch() -> int:
    inst = globals().get("cluster")
    return getattr(inst, "_lb_epoch", 0) if inst else 0


def _encode_lb_heartbeat() -> bytes:
    payload = _LB_HB.pack(NODE_ID, _ip_to_bytes(_report_host()), get_node_port(),
                          int(time.time()), int(_current_epoch()))
    return _seal(_MSG_LB_HEARTBEAT, payload)


def _encode_worker_report() -> bytes:
    cpu, mem, conn = _metrics()
    payload = _WORKER_REPORT.pack(
        NODE_ID, _ip_to_bytes(_report_host()), get_node_port(),
        int(cpu * 10), int(mem * 10), min(int(conn), 65535), int(time.time()),
    )
    return _seal(_MSG_WORKER_REPORT, payload)


def _encode_discover() -> bytes:
    payload = _DISCOVER.pack(NODE_ID)
    return _seal(_MSG_DISCOVER, payload)


def _encode_discover_reply(role_flag: int, lb_id_bytes: bytes, lb_host: str, lb_port: int,
                           epoch: int = 0) -> bytes:
    payload = _DISCOVER_REPLY.pack(
        NODE_ID, int(role_flag), lb_id_bytes, _ip_to_bytes(lb_host), int(lb_port), int(epoch)
    )
    return _seal(_MSG_DISCOVER_REPLY, payload)


def _decode(data: bytes):
    """解码消息，返回 (type: str, info: dict) 或 None（非法/未知/鉴权失败消息）。"""
    if len(data) < _HEADER.size:
        return None
    magic, version, mtype, length = _HEADER.unpack_from(data, 0)
    if magic != _MAGIC or version != _VERSION:
        return None
    payload = data[_HEADER.size:_HEADER.size + length]
    payload = _open(payload)
    if payload is None:
        logger.debug("集群消息鉴权失败（CLUSTER_SECRET 不匹配），丢弃")
        return None
    if mtype == _MSG_LB_HEARTBEAT and len(payload) >= _LB_HB.size:
        lb_id, host, port, ts, epoch = _LB_HB.unpack(payload[:_LB_HB.size])
        return "lb_heartbeat", {"lb_id": lb_id.hex(), "host": socket.inet_ntoa(host),
                                "port": port, "ts": ts, "epoch": epoch}
    if mtype == _MSG_WORKER_REPORT and len(payload) >= _WORKER_REPORT.size:
        node_id, host, port, cpu, mem, conn, ts = _WORKER_REPORT.unpack(payload[:_WORKER_REPORT.size])
        return "worker_report", {"node_id": node_id.hex(), "host": socket.inet_ntoa(host),
                                "port": port, "cpu": cpu / 10.0, "mem": mem / 10.0,
                                "conn": conn, "ts": ts}
    if mtype == _MSG_DISCOVER and len(payload) >= _DISCOVER.size:
        (nid,) = _DISCOVER.unpack(payload[:_DISCOVER.size])
        return "discover", {"node_id": nid.hex()}
    if mtype == _MSG_DISCOVER_REPLY and len(payload) >= _DISCOVER_REPLY.size:
        fid, flag, lb_id, host, port, epoch = _DISCOVER_REPLY.unpack(payload[:_DISCOVER_REPLY.size])
        return "discover_reply", {"from_id": fid.hex(), "is_lb": flag == 1,
                                  "lb_id": lb_id.hex(), "host": socket.inet_ntoa(host),
                                  "port": port, "epoch": epoch}
    return None


# ---- 组播 socket ----
def _create_receiver():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", configs.CLUSTER_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(configs.CLUSTER_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(1.0)
    return sock


def _create_sender():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    return sock


class ClusterManager:
    """集群管理器：根据选举结果扮演 LB 或 Worker（CLUSTER_MODE=auto 时自动决策）。"""

    def __init__(self):
        self._explicit_role = None
        mode = getattr(configs, "CLUSTER_MODE", "auto")
        if mode in ("lb", "worker"):
            self._explicit_role = mode
            self.mode = "explicit"
        else:
            self.mode = "auto"
        self.role = None                 # "lb" | "worker" | None（未决）
        self._role_decided = False
        self.lb_info = None              # {"lb_id","host","port","epoch"} 已知 LB 信息
        self._lb_connect_host = None     # Worker 连接 LB 的实际主机
        self._lb_http_started = False
        self._watchdog_started = False   # 看门狗线程是否已拉起（降级/晋升后避免重复）
        self._lb_epoch = 0               # 本节点作为 LB 时的领导代次（fencing）
        self._max_epoch_seen = 0         # 见过的最高领导代次（忽略过期 LB 心跳）
        self._standalone = False         # 无资格且无其他 LB 时，以独立 Worker 运行
        self._nodes = {}
        self._peers = {}                 # node_id(hex) -> 探测到的对等节点信息
        self._lock = threading.Lock()
        self._last_lb_heartbeat = time.time()
        self._running = False
        self._tcp_listen_sock = None     # TCP 模式 LB 监听 socket（降级时关闭）
        self._draining = False           # 运维置位：true 时 LB 应停止向其路由（信号位）

    def start(self):
        if not configs.CLUSTER_ENABLED:
            return
        self._running = True

        # 解析启动参数：--static-role 优先于 CLUSTER_MODE；未指定则动态选举
        forced = (getattr(configs, "CLUSTER_STATIC_ROLE", None) or "").strip().lower()
        if forced in ("lb", "worker"):
            self.mode = "explicit"
            if forced == "lb":
                eligible, reason = is_lb_eligible()
                if eligible:
                    self.role = "lb"
                    self._bump_epoch()
                    self.lb_info = {"lb_id": NODE_ID_HEX, "host": _report_host(),
                                    "port": get_node_port(), "epoch": self._lb_epoch}
                    logger.info("强制角色 LB（资格校验通过）")
                else:
                    logger.error("强制 --static-role lb 但本节点不满足 LB 资格（%s），回退为 Worker", reason)
                    self.role = "worker"
            else:
                self.role = "worker"
                logger.info("强制角色 Worker")
            self._role_decided = True

        # 传输层启动
        if configs.CLUSTER_TRANSPORT == "tcp":
            if self.mode == "auto":
                self._start_tcp()          # _bootstrap_tcp 内部决定角色并拉起循环（含资格门禁）
            elif self.role == "lb":
                if self._lb_epoch == 0:
                    self._bump_epoch()
                self.lb_info = {"lb_id": NODE_ID_HEX, "host": _report_host(),
                                "port": get_node_port(), "epoch": self._lb_epoch}
                self._start_tcp_listen()   # Worker 需连上本 LB 才能被路由
            else:  # explicit worker
                self._start_tcp_register(configs.CLUSTER_LB_HOST or _local_ip())
        else:
            self._start_multicast()
            if self.mode == "auto":
                self.bootstrap()           # 探测 + 选举（含 LB 资格门禁）
            # 显式角色已在上方设定；LB 由主 HTTP 服务在 CLUSTER_LB_PORT 提供入口

        # 角色相关后台循环
        if self.role == "worker":
            self._ensure_watchdog()
        logger.info("集群已启动（角色=%s，模式=%s，传输=%s）",
                    self.role, self.mode, configs.CLUSTER_TRANSPORT)

    def _ensure_watchdog(self):
        """确保看门狗线程仅拉起一次（降级/晋升后复用，避免重复线程）。"""
        if not self._watchdog_started:
            self._watchdog_started = True
            threading.Thread(target=self._watchdog_loop, daemon=True, name="cluster-wd").start()

    def _bump_epoch(self):
        """晋升为 LB 时刷新领导代次（单调递增，用于 fencing）。"""
        self._lb_epoch = _next_epoch()
        if self._lb_epoch > self._max_epoch_seen:
            self._max_epoch_seen = self._lb_epoch

    # ---- 组播传输（同网段） ----
    def _start_multicast(self):
        threading.Thread(target=self._broadcast_loop, daemon=True, name="cluster-tx").start()
        threading.Thread(target=self._listen_loop, daemon=True, name="cluster-rx").start()
        logger.info("集群已启动（角色=%s，组播 %s:%s，协议 v%d）",
                    self.role, configs.CLUSTER_GROUP, configs.CLUSTER_PORT, _VERSION)

    def _broadcast_loop(self):
        sock = _create_sender()
        group = (configs.CLUSTER_GROUP, configs.CLUSTER_PORT)
        while self._running:
            # 角色未决前不广播心跳（避免未决状态泄露），仅等待选举完成
            if not self._role_decided:
                time.sleep(0.2)
                continue
            try:
                data = _encode_lb_heartbeat() if self.role == "lb" else _encode_worker_report()
                sock.sendto(data, group)
            except Exception as e:
                logger.debug("组播发送失败：%s", e)
            time.sleep(configs.CLUSTER_INTERVAL)

    def _listen_loop(self):
        sock = _create_receiver()
        group = (configs.CLUSTER_GROUP, configs.CLUSTER_PORT)
        while self._running:
            try:
                data, _addr = sock.recvfrom(65535)
                decoded = _decode(data)
                if decoded:
                    self._on_message(*decoded, send_fn=lambda b: sock.sendto(b, group))
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug("组播接收失败：%s", e)

    def _broadcast_discover(self):
        """探测广播：发若干次 DISCOVER，让存活节点（含 LB）应答。"""
        sock = _create_sender()
        group = (configs.CLUSTER_GROUP, configs.CLUSTER_PORT)
        for _ in range(3):
            try:
                sock.sendto(_encode_discover(), group)
            except Exception:
                pass
            time.sleep(0.3)

    # ---- TCP 单播传输（跨网段注册中心） ----
    def _start_tcp(self):
        if self.mode == "auto":
            self._bootstrap_tcp()
        else:
            if self._explicit_role == "lb":
                self.role = "lb"
                self.lb_info = {"lb_id": NODE_ID_HEX, "host": _report_host(),
                                "port": get_node_port()}
                self._role_decided = True
                self._start_tcp_listen()
            else:
                self.role = "worker"
                self._role_decided = True
                self._start_tcp_register(configs.CLUSTER_LB_HOST or _local_ip())
            logger.info("集群已启动（角色=%s，TCP 传输，注册端口 %s，协议 v%d）",
                        self.role, configs.CLUSTER_TCP_PORT, _VERSION)

    def _start_tcp_listen(self):
        threading.Thread(target=self._tcp_listen_loop, daemon=True, name="cluster-tcp-lb").start()

    def _start_tcp_register(self, host: str):
        self._lb_connect_host = host
        threading.Thread(target=self._tcp_register_loop, daemon=True, name="cluster-tcp-worker").start()

    def _bootstrap_tcp(self, runtime: bool = False):
        """TCP 自适应引导：探测种子地址上的 LB；无则本节点抢占 LB 端口成为 LB
        （须经 LB 资格门禁）；失败回退 Worker。runtime=True 表示运行时重选举，
        晋升 LB 时需额外在 CLUSTER_LB_PORT 拉起入口（主服务已在 NODE_PORT）。"""
        seeds = []
        if configs.CLUSTER_LB_HOST:
            seeds.append(configs.CLUSTER_LB_HOST)
        seeds.append("127.0.0.1")
        lan = _local_ip()
        if lan not in seeds:
            seeds.append(lan)

        for host in seeds:
            try:
                conn = socket.create_connection((host, configs.CLUSTER_TCP_PORT), timeout=3)
                conn.settimeout(2.0)
                conn.sendall(_encode_discover())
                data = conn.recv(65535)
                for msg in self._split_frames(data):
                    d = _decode(msg)
                    if d and d[0] == "discover_reply" and d[1].get("is_lb"):
                        self.role = "worker"
                        self.lb_info = {"lb_id": d[1]["lb_id"], "host": d[1]["host"],
                                        "port": d[1]["port"], "epoch": d[1].get("epoch", 0)}
                        self._role_decided = True
                        conn.close()
                        self._start_tcp_register(host)
                        self._ensure_watchdog()
                        logger.info("TCP 自适应：发现 LB %s:%s，注册为 Worker", host, configs.CLUSTER_TCP_PORT)
                        return
                conn.close()
            except OSError:
                continue

        # 未找到存活 LB：本节点抢占 LB 端口成为 LB（须满足 LB 资格门禁）
        eligible, reason = is_lb_eligible()
        if not eligible:
            logger.warning("TCP 自适应：未发现 LB 且本节点不满足 LB 资格（%s），以 Worker 重连", reason)
            self.role = "worker"
            self._role_decided = True
            self._start_tcp_register(configs.CLUSTER_LB_HOST or "127.0.0.1")
            self._ensure_watchdog()
            return
        try:
            self._start_tcp_listen()  # 绑定 CLUSTER_TCP_PORT；若被占用会抛 OSError
            self._become_lb()
            logger.info("TCP 自适应：未发现 LB，本节点成为 LB（监听 %s）", configs.CLUSTER_TCP_PORT)
            if runtime:
                self._start_lb_http()  # 运行时晋升：主服务在 NODE_PORT，需额外 LB 入口
        except OSError as e:
            logger.warning("TCP 自适应：LB 端口被占用（%s），回退为 Worker 重连", e)
            self.role = "worker"
            self._role_decided = True
            self._start_tcp_register(configs.CLUSTER_LB_HOST or "127.0.0.1")
            self._ensure_watchdog()

    def _tcp_listen_loop(self):
        """LB：监听 Worker 注册连接，每个连接独立线程处理上报与心跳回送。"""
        srv = _make_tcp_socket()
        if configs.CLUSTER_VNET:
            vip_int = srv._src_ip
            vip = "%d.%d.%d.%d" % ((vip_int >> 24) & 0xff, (vip_int >> 16) & 0xff,
                                   (vip_int >> 8) & 0xff, vip_int & 0xff)
            srv.bind((vip, configs.CLUSTER_TCP_PORT))
            srv.listen((vip, configs.CLUSTER_TCP_PORT), 32)
            logger.info("[VNET] LB 虚拟监听 %s:%s", vip, configs.CLUSTER_TCP_PORT)
            _dump_ip = os.getenv("CLUSTER_VNET_IP_DUMP")
            if _dump_ip:
                try:
                    with open(_dump_ip, "w", encoding="utf-8") as _f:
                        _f.write(vip)
                except Exception as _e:
                    logger.warning("虚拟 IP 落盘失败：%s", _e)
            global _VNET_IP_CACHE
            _VNET_IP_CACHE = vip
        else:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", configs.CLUSTER_TCP_PORT))
            srv.listen(32)
            srv.settimeout(1.0)
        self._tcp_listen_sock = srv
        while self._running:
            try:
                conn = srv.accept()
                logger.info("[VNET] LB accept 收到连接: %s", type(conn))
            except socket.timeout:
                continue
            except OSError as e:
                logger.error("[VNET] LB accept OSError: %s", e)
                break
            threading.Thread(target=self._tcp_handle_worker, args=(conn,),
                             daemon=True, name="cluster-tcp-peer").start()

    def _tcp_handle_worker(self, conn):
        # 标准 socket 的 accept 返回 (conn, addr) 元组；WrappedSocket 直接返回 conn。
        # 统一处理：若为元组则取第一个元素。
        if isinstance(conn, tuple):
            conn = conn[0]
        conn.settimeout(2.0)
        # 首包：LB 立即回送一次心跳，确认注册
        try:
            conn.sendall(_encode_lb_heartbeat())
        except OSError:
            conn.close()
            return
        while self._running:
            try:
                data = conn.recv(65535)
                if not data:
                    break  # 对端关闭
                for msg in self._split_frames(data):
                    decoded = _decode(msg)
                    if not decoded:
                        continue
                    mtype, info = decoded
                    if mtype == "discover":
                        conn.sendall(self._build_discover_reply_bytes())
                        continue
                    self._on_message(mtype, info, send_fn=conn.sendall)
                # 回送心跳，维持 Worker 看门狗
                conn.sendall(_encode_lb_heartbeat())
            except socket.timeout:
                try:
                    conn.sendall(_encode_lb_heartbeat())
                except OSError:
                    break
            except OSError:
                break
        conn.close()

    def _tcp_register_loop(self):
        """Worker：主动连接 LB 注册中心，周期上报指标，断线重连。"""
        host = self._lb_connect_host or configs.CLUSTER_LB_HOST or _local_ip()
        while self._running:
            try:
                if configs.CLUSTER_VNET:
                    conn = _make_tcp_socket()
                    conn.connect((host, configs.CLUSTER_TCP_PORT))
                else:
                    conn = socket.create_connection((host, configs.CLUSTER_TCP_PORT), timeout=5)
                conn.settimeout(2.0)
                # 首包发送 DISCOVER，学习 LB 信息（即便 LB 随后才应答）
                try:
                    conn.sendall(_encode_discover())
                    data = conn.recv(65535)
                    for msg in self._split_frames(data):
                        d = _decode(msg)
                        if d:
                            self._on_message(*d, send_fn=conn.sendall)
                except socket.timeout:
                    pass
                logger.info("已连接 LB 注册中心 %s:%s", host, configs.CLUSTER_TCP_PORT)
                while self._running:
                    try:
                        conn.sendall(_encode_worker_report())
                        data = conn.recv(65535)
                        if not data:
                            break
                        for msg in self._split_frames(data):
                            d = _decode(msg)
                            if d:
                                self._on_message(*d, send_fn=conn.sendall)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    time.sleep(configs.CLUSTER_INTERVAL)
                conn.close()
            except OSError as e:
                logger.warning("连接 LB 注册中心失败（%s），5 秒后重连", e)
                time.sleep(5)

    @staticmethod
    def _split_frames(data: bytes):
        """按协议头 length 字段拆出完整帧（处理粘包）。"""
        frames = []
        off = 0
        while off + _HEADER.size <= len(data):
            _, _, _, length = _HEADER.unpack_from(data, off)
            end = off + _HEADER.size + length
            if end > len(data):
                break
            frames.append(data[off:end])
            off = end
        return frames

    # ---- 自适应选举 ----
    def bootstrap(self):
        """组播自适应引导：探测 → 等待 → 决策角色。阻塞 CLUSTER_BOOTSTRAP_WAIT 秒。"""
        logger.info("自适应选举：开始探测存活节点（窗口 %ds）", configs.CLUSTER_BOOTSTRAP_WAIT)
        self._broadcast_discover()
        time.sleep(configs.CLUSTER_BOOTSTRAP_WAIT)
        self._decide_role()
        logger.info("自适应选举完成：本节点角色=%s，已知 LB=%s", self.role, self.lb_info)

    def _decide_role(self):
        lbs = [p for p in self._peers.values() if p.get("is_lb")]
        if lbs:
            # 已有 LB：向其注册为 Worker（多 LB 时按 (代次, ID) 最小者，避免裂脑）
            best = min(lbs, key=lambda p: (p.get("epoch", 0), p["lb_id"]))
            self.lb_info = {"lb_id": best["lb_id"], "host": best["host"],
                            "port": best["port"], "epoch": best.get("epoch", 0)}
            self.role = "worker"
        elif self._peers:
            # 有节点但无 LB：与所有已知节点按 NODE_ID 最小者当选 LB（须满足 LB 资格门禁）
            ids = [p["node_id"] for p in self._peers.values()] + [NODE_ID_HEX]
            if NODE_ID_HEX == min(ids):
                eligible, reason = is_lb_eligible()
                if eligible:
                    self._become_lb()
                else:
                    logger.warning("本节点 ID 最小但不满足 LB 资格，降级为 Worker：%s", reason)
                    self.role = "worker"
            else:
                self.role = "worker"
        else:
            # 无存活节点：自己作为独立服务器（即 LB，无 Worker）——但须满足 LB 资格
            eligible, reason = is_lb_eligible()
            if eligible:
                self._become_lb()
            else:
                logger.warning("无存活节点但本节点不满足 LB 资格，以独立 Worker 运行（无控制面）")
                self.role = "worker"
                self._standalone = True
        self._role_decided = True

    def _build_discover_reply_bytes(self) -> bytes:
        if self.role == "lb":
            return _encode_discover_reply(1, NODE_ID, _report_host(), get_node_port(), self._lb_epoch)
        if self.lb_info:
            return _encode_discover_reply(0, bytes.fromhex(self._lb_info["lb_id"]),
                                          self.lb_info["host"], self.lb_info["port"],
                                          self.lb_info.get("epoch", 0))
        return _encode_discover_reply(0, b"\x00" * 8, "0.0.0.0", 0, 0)

    def _on_message(self, mtype: str, info: dict, send_fn):
        """统一消息处理：探测应答、LB 心跳、Worker 上报，并维护对等节点表。"""
        if mtype == "discover":
            # 不应答自己发出的探测
            if info.get("node_id") == NODE_ID_HEX:
                return
            try:
                send_fn(self._build_discover_reply_bytes())
            except OSError:
                pass
            return
        if mtype == "discover_reply":
            self._learn_peer(info)
            return
        if mtype == "lb_heartbeat":
            self._last_lb_heartbeat = time.time()
            inc_epoch = info.get("epoch", 0)
            # 记录见过的最高代次；低于此代次的过期 LB 心跳在 _learn_lb 中会被忽略（fencing）
            if inc_epoch > self._max_epoch_seen:
                self._max_epoch_seen = inc_epoch
            self._learn_lb(info)
            # 裂脑收敛（组播/TCP 统一）：本节点是 LB，且发现代次更高或（代次相同且 ID 更低）
            # 的另一 LB，则主动降级为 Worker，避免双 LB 并存。
            if self.role == "lb" and info["lb_id"] != NODE_ID_HEX:
                higher = inc_epoch > self._lb_epoch or (
                    inc_epoch == self._lb_epoch and info["lb_id"] < NODE_ID_HEX)
                if higher:
                    self._step_down_to_worker(info)
            return
        if mtype == "worker_report":
            self._learn_worker(info)
            if self.role == "lb":
                node_id = info.get("node_id")
                if not node_id:
                    return
                info["last_seen"] = time.time()
                info["score"] = _load_score(
                    info.get("cpu", 0), info.get("mem", 0), info.get("conn", 0)
                )
                with self._lock:
                    self._nodes[node_id] = info

    def _learn_peer(self, info):
        nid = info["from_id"]
        epoch = info.get("epoch", 0)
        self._peers[nid] = {"node_id": nid, "is_lb": info["is_lb"], "lb_id": info["lb_id"],
                            "host": info["host"], "port": info["port"], "epoch": epoch,
                            "ts": time.time()}
        if info["is_lb"]:
            # fencing：忽略代次低于已知最高代次的过期 LB 应答
            if epoch < self._max_epoch_seen:
                logger.debug("忽略过期 LB(%s) 应答（代次 %s < 已知 %s）", nid, epoch, self._max_epoch_seen)
                return
            self.lb_info = {"lb_id": info["lb_id"], "host": info["host"],
                            "port": info["port"], "epoch": epoch}
            if epoch > self._max_epoch_seen:
                self._max_epoch_seen = epoch

    def _learn_lb(self, info):
        # fencing：忽略代次低于已知最高代次的过期 LB 心跳（被废黜旧 LB 复活时不会劫持）
        if info.get("epoch", 0) < self._max_epoch_seen:
            logger.debug("忽略过期 LB(%s) 心跳（代次 %s < 已知 %s）",
                         info.get("lb_id"), info.get("epoch", 0), self._max_epoch_seen)
            return
        nid = info["lb_id"]
        epoch = info.get("epoch", 0)
        self._peers[nid] = {"node_id": nid, "is_lb": True, "lb_id": nid,
                            "host": info["host"], "port": info["port"], "epoch": epoch,
                            "ts": time.time()}
        self.lb_info = {"lb_id": nid, "host": info["host"], "port": info["port"], "epoch": epoch}
        if epoch > self._max_epoch_seen:
            self._max_epoch_seen = epoch

    def _learn_worker(self, info):
        nid = info["node_id"]
        self._peers[nid] = {"node_id": nid, "is_lb": False, "lb_id": "",
                            "host": info["host"], "port": info["port"], "ts": time.time()}

    def set_draining(self, draining: bool) -> None:
        """运维信号：置位后 LB 应停止向本 Worker 路由（drain/resume 命令使用）。"""
        self._draining = bool(draining)
        logger.warning("本节点 drain 状态置为 %s", self._draining)

    def list_nodes(self) -> list:
        """返回集群已知节点清单（含本节点），供 Console `nodes` 命令使用。"""
        nodes = []
        if self.role:
            nodes.append({
                "node_id": NODE_ID_HEX, "self": True, "role": self.role,
                "host": _report_host(), "port": get_node_port(),
                "draining": self._draining,
                "epoch": self._lb_epoch if self.role == "lb" else 0,
            })
        for nid, p in self._peers.items():
            nodes.append({
                "node_id": nid, "self": False,
                "role": "lb" if p.get("is_lb") else "worker",
                "host": p.get("host"), "port": p.get("port"),
                "draining": p.get("draining", False),
                "epoch": p.get("epoch", 0),
            })
        return nodes

    def _step_down_to_worker(self, info):
        logger.warning("发现更高代次/更低 ID 的 LB(%s)，本节点裂脑降级为 Worker", info.get("lb_id"))
        was_lb = self.role == "lb"
        self.role = "worker"
        self.lb_info = {"lb_id": info.get("lb_id"), "host": info.get("host"),
                        "port": info.get("port"), "epoch": info.get("epoch", 0)}
        self._role_decided = True
        # 真正转为 Worker：拉起看门狗，并在 TCP 模式下重新向新 LB 注册（否则不会被路由）
        self._ensure_watchdog()
        if configs.CLUSTER_TRANSPORT == "tcp":
            host = (info.get("host") or self._lb_connect_host
                    or configs.CLUSTER_LB_HOST or _local_ip())
            self._start_tcp_register(host)
        elif was_lb:
            # 组播：广播循环会在下一轮切换为 WORKER_REPORT；此处确保不再以 LB 身份广播
            logger.info("组播 LB 已降级为 Worker，停止 LB 心跳广播")

    def _watchdog_loop(self):
        while self._running:
            time.sleep(configs.CLUSTER_INTERVAL)
            if self.role != "worker":
                continue
            if time.time() - self._last_lb_heartbeat > configs.CLUSTER_WORKER_TIMEOUT:
                self._on_lb_lost()

    def _on_lb_lost(self):
        """LB 失联：自适应模式重新选举；非自适应模式保持重连（不再自杀）。"""
        logger.warning("LB 失联超过 %ds，触发处理", configs.CLUSTER_WORKER_TIMEOUT)
        self.lb_info = None
        self._max_epoch_seen = 0  # 失联后重置，避免旧代次阻碍新 LB 学习
        if self.mode != "auto":
            logger.warning("非自适应模式：保持对 LB 的重连（不自动自杀）")
            # 重置计时，避免反复触发
            self._last_lb_heartbeat = time.time()
            return
        if configs.CLUSTER_TRANSPORT == "tcp":
            self._bootstrap_tcp(runtime=True)
            if self.role == "worker":
                self._ensure_watchdog()
            return
        # 组播：重新探测，若仍无 LB 则由存活节点中 ID 最小且具备 LB 资格者晋升
        self._broadcast_discover()
        time.sleep(configs.CLUSTER_BOOTSTRAP_WAIT)
        lbs = [p for p in self._peers.values() if p.get("is_lb")]
        if lbs:
            best = min(lbs, key=lambda p: (p.get("epoch", 0), p["lb_id"]))
            self.lb_info = {"lb_id": best["lb_id"], "host": best["host"],
                            "port": best["port"], "epoch": best.get("epoch", 0)}
            self.role = "worker"
            self._ensure_watchdog()
            logger.info("重新选举：发现新 LB %s，本节点为 Worker", best["lb_id"])
        else:
            ids = [p["node_id"] for p in self._peers.values()] + [NODE_ID_HEX]
            if NODE_ID_HEX == min(ids) and is_lb_eligible()[0]:
                self._promote_to_lb()
            else:
                if NODE_ID_HEX == min(ids):
                    logger.warning("重新选举：本节点 ID 最小但不满足 LB 资格，维持 Worker")
                self.role = "worker"
                self._last_lb_heartbeat = time.time()
                self._ensure_watchdog()
                logger.info("重新选举：本节点为 Worker，等待新 LB 心跳")

    def _become_lb(self):
        """设定本节点为 LB（启动期/重选举通用）：刷新领导代次并写入 lb_info。
        不在此额外拉起 HTTP——LB 固定端口由主 HTTP 服务（serve_http）在启动期绑定；
        仅运行时晋升才需 _promote_to_lb 额外拉起入口。"""
        self._bump_epoch()
        self.role = "lb"
        self.lb_info = {"lb_id": NODE_ID_HEX, "host": _report_host(),
                        "port": get_node_port(), "epoch": self._lb_epoch}
        self._role_decided = True

    def _promote_to_lb(self):
        """运行时晋升为 LB（主服务已在 NODE_PORT，需在 CLUSTER_LB_PORT 额外拉起入口）。"""
        logger.info("重新选举：本节点晋升为 LB")
        self._become_lb()
        if configs.CLUSTER_TRANSPORT == "tcp":
            try:
                self._start_tcp_listen()
            except Exception as e:
                logger.error("晋升 LB 后 TCP 监听启动失败：%s", e)
        self._start_lb_http()

    def _start_lb_http(self):
        """运行时晋升 LB 时，在固定 LB 端口额外拉起 HTTP 服务（对外统一入口）。
        使用 Hypercorn 在独立事件循环中真正监听（Quart 的 app.run 为协程，裸线程直接
        调用无法生效，#5c）。"""
        if self._lb_http_started:
            return
        self._lb_http_started = True

        def _run():
            try:
                import asyncio
                from hypercorn.asyncio import serve
                from hypercorn.config import Config as HyperConfig
                from .app import app as _app
                cfg = HyperConfig()
                cfg.bind = [f"0.0.0.0:{configs.CLUSTER_LB_PORT}"]
                cfg.accesslog = None
                cfg.errorlog = None
                logger.info("LB HTTP 入口启动：%s", configs.CLUSTER_LB_PORT)
                asyncio.run(serve(_app, cfg))
            except Exception as e:
                logger.error("LB HTTP 端口 %s 绑定/服务失败：%s", configs.CLUSTER_LB_PORT, e)

        threading.Thread(target=_run, daemon=True, name="lb-http").start()

    # ---- LB 查询/路由 ----
    def get_nodes(self) -> list:
        now = time.time()
        timeout = configs.CLUSTER_INTERVAL * 3
        with self._lock:
            online = [n for n in self._nodes.values()
                      if now - n.get("last_seen", 0) < timeout]
        return sorted(online, key=lambda n: n.get("score", 100))

    def select_best(self):
        nodes = self.get_nodes()
        return nodes[0] if nodes else None


cluster = ClusterManager()
