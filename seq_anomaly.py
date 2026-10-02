"""
序列异常检测 —— Tiny GRU / Tiny Transformer 识别「异常的接口访问顺序」

问题背景:
  正常用户/设备的 API 调用顺序是有规律的（先 /login，再 /dashboard，再 /chat/...）。
  而扫描器、凭据填充、越权探测等自动化攻击的访问顺序是反常的（/admin → /api/user/...
  → 大量 404、反复横跳、跳过正常前置步骤）。本模块用一个轻量序列模型，对「设备/账号
  的接口访问顺序」做 next-token 预测，把「预测不到的下一步」量化为 surprise 分数，
  当 surprise 持续显著高于该设备自身的历史基线时判定为异常。

模型设计（零依赖、纯 Python）:
  - 词表: 把每个请求归一化成「方法 + 路径前缀」的 token（如 POST /api/chat/completions
    → chat_completions），增量构建。
  - 序列模型（二选一或融合，由配置 SEQ_ANOMALY_MODEL 决定）:
      * TinyGRU     : 1 层门控循环单元，把 token 序列编码成定长 h。
      * TinyTransformer: 1 层自注意力（含位置编码），平均池化成 h。
    模型权重在启动时用固定随机种子初始化后**保持不变**（reservoir / 随机特征映射），
    仅最后的线性读出层 W_out·h + b 在线增量训练。这是 tiny 模型常见且数值稳定的做法：
    循环/注意力负责把序列映射成有判别力的表征，读出层负责把它拟合到「下一步 token」
    这个目标上。用固定随机循环网络 + 可训练读出层，等价于 Echo State / reservoir 思路。
  - 在线训练: 每个请求后，用观测到的真实 token 对读出层做一步 SGD（cross-entropy 梯度），
    因此模型会自适应「该设备逐渐演化出的正常行为」，不会把老用户的新习惯长期误判。
  - 异常判定: 维护每个 tracking-key 的 surprise 的 EMA 作为基线；当单次 surprise 超过
    基线 * factor 且样本数达到 MIN_SAMPLES 时，判定为异常（detect-only，默认不拦截，
    由中间件决定是否封禁）。

线程安全: 本模块在 asyncio.to_thread 线程池下被并发调用，故对所有可变状态加锁。
"""
import json
import logging
import math
import os
import threading
import time

from . import configs

logger = logging.getLogger("seq_anomaly")


# ===========================================================================
# 小型矩阵/向量工具（纯 Python，d 很小，性能足够）
# ===========================================================================
def _zeros(n):
    return [0.0] * n


def _rand_vec(n, rng):
    return [rng.uniform(-1.0, 1.0) for _ in range(n)]


def _mat_vec(M, v):
    """(m x n) @ (n,) -> (m,)"""
    out = [0.0] * len(M)
    for i in range(len(M)):
        row = M[i]
        s = 0.0
        for j in range(len(v)):
            s += row[j] * v[j]
        out[i] = s
    return out


def _add(a, b):
    return [a[i] + b[i] for i in range(len(a))]


def _dot(a, b):
    s = 0.0
    for i in range(len(a)):
        s += a[i] * b[i]
    return s


def _softmax(xs):
    m = max(xs)
    exps = [math.exp(x - m) for x in xs]
    s = sum(exps) or 1e-12
    return [e / s for e in exps]


# ===========================================================================
# 计算后端自动选择（依赖存在性 + 系统配置 + 工作负载）
# ===========================================================================
# 策略：
#   1. 配置 SEQ_ANOMALY_BACKEND 显式指定时尊重之（指定了但未安装则降级并记录原因）；
#   2. auto 模式按「工作负载是否值得」选：
#      - torch 仅当 (hidden>=32 或 model=both) 且 核数>=2 且可用内存>=2048MB ——
#        tiny 模型（hidden<32 单模型）单次推理被框架调度开销支配，numpy 才是最优；
#      - numpy 可用则优于纯 Python（d 维 matvec 提速约一个数量级）；
#      - 都没有回退纯 Python（功能等价，只是慢）。
#   3. 三个后端的权重随机数抽取顺序严格一致（同一个 Python random.Random 流），
#      reservoir 跨后端可复现，读出层快照可跨后端加载。
def _select_backend() -> dict:
    override = str(getattr(configs, "SEQ_ANOMALY_BACKEND", "auto") or "auto").strip().lower()
    cores = os.cpu_count() or 1
    ram_avail = 0
    try:
        import psutil
        ram_avail = int(psutil.virtual_memory().available / (1024 * 1024))
    except Exception:
        pass

    def probe(name):
        try:
            return __import__(name)
        except Exception:
            return None

    np_mod = probe("numpy")
    th_mod = probe("torch")
    hidden = max(8, int(getattr(configs, "SEQ_ANOMALY_HIDDEN", 16) or 16))
    model_kind = (getattr(configs, "SEQ_ANOMALY_MODEL", "gru") or "gru").strip().lower()
    wants_torch = hidden >= 32 or model_kind == "both"

    if override in ("python", "pure"):
        backend, reason = "python", "配置指定纯 Python"
    elif override == "torch":
        if th_mod is not None:
            backend, reason = "torch", "配置指定 torch"
        else:
            backend = "numpy" if np_mod is not None else "python"
            reason = "配置指定 torch 但未安装，自动降级"
    elif override == "numpy":
        if np_mod is not None:
            backend, reason = "numpy", "配置指定 numpy"
        else:
            backend, reason = "python", "配置指定 numpy 但未安装，回退纯 Python"
    else:  # auto
        if th_mod is not None and np_mod is not None and wants_torch and cores >= 2 and ram_avail >= 2048:
            backend = "torch"
            reason = (f"auto: 工作负载需要(hidden={hidden},model={model_kind}) "
                      f"+ {cores} 核 / 可用内存 {ram_avail}MB")
        elif np_mod is not None:
            backend = "numpy"
            reason = f"auto: tiny 模型(hidden={hidden}) numpy 单次推理最快"
        else:
            backend = "python"
            reason = "auto: numpy/torch 均不可用，纯 Python 兜底"

    if backend == "torch" and th_mod is not None:
        try:
            th_mod.set_num_threads(min(cores, 4))  # 2C/4T 上防 oversubscription
        except Exception:
            pass
    return {
        "backend": backend,
        "reason": reason,
        "cores": cores,
        "ram_avail_mb": ram_avail,
        "numpy_version": getattr(np_mod, "__version__", None),
        "torch_version": getattr(th_mod, "__version__", None),
        "wants_torch": wants_torch,
    }


# ===========================================================================
# numpy / torch 加速实现（权重抽取顺序与纯 Python 版严格一致）
# ===========================================================================
def _draw_mat(py_rng, d, factory):
    """按纯 Python 版的抽取顺序画一个 d×d 随机矩阵。factory(list-of-lists) -> 矩阵对象"""
    return factory([[py_rng.uniform(-1.0, 1.0) for _ in range(d)] for _ in range(d)])


class _NumpyGRU:
    """与 _TinyGRU 数值等价的 numpy 实现。"""

    def __init__(self, d, rng):
        import numpy as np
        self.np = np
        self.d = d
        self.emb = {}
        mk = lambda rows: np.array(rows, dtype=np.float64)
        self.Wz = _draw_mat(rng, d, mk)
        self.Uz = _draw_mat(rng, d, mk)
        self.bz = np.zeros(d, dtype=np.float64)
        self.Wr = _draw_mat(rng, d, mk)
        self.Ur = _draw_mat(rng, d, mk)
        self.br = np.zeros(d, dtype=np.float64)
        self.Wn = _draw_mat(rng, d, mk)
        self.Un = _draw_mat(rng, d, mk)
        self.bn = np.zeros(d, dtype=np.float64)

    def _embed(self, tid, rng):
        v = self.emb.get(tid)
        if v is None:
            v = self.np.array([rng.uniform(-1.0, 1.0) for _ in range(self.d)], dtype=self.np.float64)
            self.emb[tid] = v
        return v

    def forward(self, seq_ids, rng):
        np = self.np
        h = np.zeros(self.d, dtype=np.float64)
        for tid in seq_ids:
            x = self._embed(tid, rng)
            z = 1.0 / (1.0 + np.exp(-(self.Wz @ x + self.Uz @ h + self.bz)))
            r = 1.0 / (1.0 + np.exp(-(self.Wr @ x + self.Ur @ h + self.br)))
            n = np.tanh(self.Wn @ x + self.Un @ (r * h) + self.bn)
            h = z * h + (1.0 - z) * n
        return h.tolist()


class _NumpyTransformer:
    """与 _TinyTransformer 数值等价的 numpy 实现。"""

    def __init__(self, d, heads, rng):
        import numpy as np
        self.np = np
        self.d = d
        self.heads = heads
        self.emb = {}
        self.pos = {}
        mk = lambda rows: np.array(rows, dtype=np.float64)
        self.Wq = _draw_mat(rng, d, mk)
        self.Wk = _draw_mat(rng, d, mk)
        self.Wv = _draw_mat(rng, d, mk)
        self.Wo = _draw_mat(rng, d, mk)
        self.ffW = _draw_mat(rng, d, mk)
        self.ffb = np.zeros(d, dtype=np.float64)

    def _embed(self, tid, pos, rng):
        np = self.np
        e = self.emb.get(tid)
        if e is None:
            e = np.array([rng.uniform(-1.0, 1.0) for _ in range(self.d)], dtype=np.float64)
            self.emb[tid] = e
        p = self.pos.get(pos)
        if p is None:
            p = np.array([rng.uniform(-1.0, 1.0) for _ in range(self.d)], dtype=np.float64)
            self.pos[pos] = p
        return e + p

    def forward(self, seq_ids, rng):
        np = self.np
        if not seq_ids:
            return [0.0] * self.d
        X = np.stack([self._embed(tid, i, rng) for i, tid in enumerate(seq_ids)])
        Q = X @ self.Wq.T
        K = X @ self.Wk.T
        V = X @ self.Wv.T
        S = Q @ K.T / math.sqrt(self.d)
        S = S - S.max(axis=1, keepdims=True)
        E = np.exp(S)
        A = E / E.sum(axis=1, keepdims=True)   # exp 恒正，行和不可能为 0
        C = A @ V
        O = C @ self.Wo.T
        F = np.tanh((O + X) @ self.ffW.T + self.ffb)
        return (O + F).mean(axis=0).tolist()


class _TorchGRU:
    """与 _TinyGRU 数值等价的 torch 实现（CPU，float64）。"""

    def __init__(self, d, rng):
        import torch
        self.torch = torch
        self.d = d
        self.emb = {}
        mk = lambda rows: torch.tensor(rows, dtype=torch.float64)
        self.Wz = _draw_mat(rng, d, mk)
        self.Uz = _draw_mat(rng, d, mk)
        self.bz = torch.zeros(d, dtype=torch.float64)
        self.Wr = _draw_mat(rng, d, mk)
        self.Ur = _draw_mat(rng, d, mk)
        self.br = torch.zeros(d, dtype=torch.float64)
        self.Wn = _draw_mat(rng, d, mk)
        self.Un = _draw_mat(rng, d, mk)
        self.bn = torch.zeros(d, dtype=torch.float64)

    def _embed(self, tid, rng):
        v = self.emb.get(tid)
        if v is None:
            v = self.torch.tensor([rng.uniform(-1.0, 1.0) for _ in range(self.d)],
                                  dtype=self.torch.float64)
            self.emb[tid] = v
        return v

    def forward(self, seq_ids, rng):
        t = self.torch
        h = t.zeros(self.d, dtype=t.float64)
        for tid in seq_ids:
            x = self._embed(tid, rng)
            z = t.sigmoid(self.Wz @ x + self.Uz @ h + self.bz)
            r = t.sigmoid(self.Wr @ x + self.Ur @ h + self.br)
            n = t.tanh(self.Wn @ x + self.Un @ (r * h) + self.bn)
            h = z * h + (1.0 - z) * n
        return h.tolist()


class _TorchTransformer:
    """与 _TinyTransformer 数值等价的 torch 实现（CPU，float64）。"""

    def __init__(self, d, heads, rng):
        import torch
        self.torch = torch
        self.d = d
        self.heads = heads
        self.emb = {}
        self.pos = {}
        mk = lambda rows: torch.tensor(rows, dtype=torch.float64)
        self.Wq = _draw_mat(rng, d, mk)
        self.Wk = _draw_mat(rng, d, mk)
        self.Wv = _draw_mat(rng, d, mk)
        self.Wo = _draw_mat(rng, d, mk)
        self.ffW = _draw_mat(rng, d, mk)
        self.ffb = torch.zeros(d, dtype=torch.float64)

    def _embed(self, tid, pos, rng):
        t = self.torch
        e = self.emb.get(tid)
        if e is None:
            e = t.tensor([rng.uniform(-1.0, 1.0) for _ in range(self.d)], dtype=t.float64)
            self.emb[tid] = e
        p = self.pos.get(pos)
        if p is None:
            p = t.tensor([rng.uniform(-1.0, 1.0) for _ in range(self.d)], dtype=t.float64)
            self.pos[pos] = p
        return e + p

    def forward(self, seq_ids, rng):
        t = self.torch
        if not seq_ids:
            return [0.0] * self.d
        X = t.stack([self._embed(tid, i, rng) for i, tid in enumerate(seq_ids)])
        Q = X @ self.Wq.T
        K = X @ self.Wk.T
        V = X @ self.Wv.T
        S = (Q @ K.T) / math.sqrt(self.d)
        S = S - S.max(dim=1, keepdim=True).values
        E = t.exp(S)
        A = E / E.sum(dim=1, keepdim=True)   # exp 恒正，行和不可能为 0
        C = A @ V
        O = C @ self.Wo.T
        F = t.tanh((O + X) @ self.ffW.T + self.ffb)
        return (O + F).mean(dim=0).tolist()


# ===========================================================================
# 端点 token 归一化
# ===========================================================================
# 把路径粗化成「语义段」：去掉 ID/UUID/数字，保留 method + 前两段路径 + 已知动作。
_KNOWN_TAIL = {
    "login": "login", "logout": "logout", "register": "register",
    "completions": "chat_completions", "chat": "chat", "messages": "messages",
    "recharge": "recharge", "balance": "balance", "usage": "usage",
    "admin": "admin", "users": "admin_users", "bans": "admin_bans",
    "hooks": "admin_hooks", "announcements": "admin_announce",
    "models": "models", "upstreams": "upstreams", "keys": "apikeys",
    "oauth": "oauth", "token": "oauth_token", "introspect": "oauth_introspect",
    "console": "console", "selftest": "selftest", "health": "health",
    "friends": "social_friends", "posts": "social_posts", "transfer": "social_transfer",
    "notifications": "notifications", "settings": "settings", "dashboard": "dashboard",
}


def normalize_endpoint(method: str, path: str) -> str:
    """把 (method, path) 归一成统一 token。"""
    m = (method or "GET").upper()
    # 去查询串与协议前缀
    p = (path or "").split("?")[0].split("#")[0]
    if p.startswith("http://") or p.startswith("https://"):
        p = "/" + p.split("/", 3)[-1] if p.count("/") >= 3 else p
    segs = [s for s in p.strip("/").split("/") if s]
    # 去掉纯数字段 / UUID（避免动词表爆炸，同时让 /users/123 与 /users/456 视为同类）
    cleaned = []
    for s in segs[:3]:  # 只取前 3 段
        if s.isdigit():
            continue
        if len(s) == 36 and s.count("-") == 4:  # UUID
            continue
        cleaned.append(s)
    tail = cleaned[-1] if cleaned else ""
    sem = _KNOWN_TAIL.get(tail, None) or (cleaned[-1] if cleaned else "root")
    return f"{m.lower()}_{sem}"


# ===========================================================================
# 固定随机循环/注意力网络
# ===========================================================================
class _TinyGRU:
    """1 层 GRU，权重固定（reservoir）。forward(seq_ids) -> 定长隐藏向量。"""
    def __init__(self, d, rng):
        self.d = d
        # 随机嵌入（每个 token id 一个固定向量，增量扩展）
        self.emb = {}
        # GRU 参数（d 维）
        self.Wz = [_rand_vec(d, rng) for _ in range(d)]
        self.Uz = [_rand_vec(d, rng) for _ in range(d)]
        self.bz = _zeros(d)
        self.Wr = [_rand_vec(d, rng) for _ in range(d)]
        self.Ur = [_rand_vec(d, rng) for _ in range(d)]
        self.br = _zeros(d)
        self.Wn = [_rand_vec(d, rng) for _ in range(d)]
        self.Un = [_rand_vec(d, rng) for _ in range(d)]
        self.bn = _zeros(d)

    def _embed(self, tid, rng):
        if tid not in self.emb:
            self.emb[tid] = _rand_vec(self.d, rng)
        return self.emb[tid]

    def forward(self, seq_ids, rng):
        h = _zeros(self.d)
        for tid in seq_ids:
            x = self._embed(tid, rng)
            z = _sigmoid_vec(_add(_mat_vec(self.Wz, x), _add(_mat_vec(self.Uz, h), self.bz)))
            r = _sigmoid_vec(_add(_mat_vec(self.Wr, x), _add(_mat_vec(self.Ur, h), self.br)))
            # n = tanh(Wn·x + Un·(r*h) + bn)
            rh = [r[i] * h[i] for i in range(self.d)]
            n = _tanh_vec(_add(_mat_vec(self.Wn, x), _add(_mat_vec(self.Un, rh), self.bn)))
            h = [z[i] * h[i] + (1 - z[i]) * n[i] for i in range(self.d)]
        return h

    def _rng(self):
        return self._rng_obj

    def set_rng(self, rng):
        self._rng_obj = rng


def _sigmoid(x):
    return 1.0 / (1.0 + math.exp(-x))


def _sigmoid_vec(v):
    return [_sigmoid(x) for x in v]


def _tanh_vec(v):
    return [math.tanh(x) for x in v]


class _TinyTransformer:
    """1 层自注意力 + FFN，权重固定（reservoir）。forward -> 平均池化隐藏向量。"""

    def __init__(self, d, heads, rng):
        self.d = d
        self.heads = heads
        self.emb = {}
        self.pos = {}  # 位置 -> 固定向量
        # 注意力投影（每个 head 一个 d_h 维子空间，这里直接做全 d 投影简化）
        self.Wq = [_rand_vec(d, rng) for _ in range(d)]
        self.Wk = [_rand_vec(d, rng) for _ in range(d)]
        self.Wv = [_rand_vec(d, rng) for _ in range(d)]
        self.Wo = [_rand_vec(d, rng) for _ in range(d)]
        # FFN
        self.ffW = [_rand_vec(d, rng) for _ in range(d)]
        self.ffb = _zeros(d)

    def _embed(self, tid, pos, rng):
        if tid not in self.emb:
            self.emb[tid] = _rand_vec(self.d, rng)
        if pos not in self.pos:
            self.pos[pos] = _rand_vec(self.d, rng)
        return _add(self.emb[tid], self.pos[pos])

    def forward(self, seq_ids, rng):
        xs = [self._embed(tid, i, rng) for i, tid in enumerate(seq_ids)]
        if not xs:
            return _zeros(self.d)
        # 自注意力（简化：全连接注意力，非分头以减小代码量；heads 仅作缩放系数）
        hs = []
        for i in range(len(xs)):
            qi = _mat_vec(self.Wq, xs[i])
            scores = []
            for j in range(len(xs)):
                kj = _mat_vec(self.Wk, xs[j])
                scores.append(_dot(qi, kj) / math.sqrt(self.d))
            att = _softmax(scores)
            ctx = _zeros(self.d)
            for j in range(len(xs)):
                vj = _mat_vec(self.Wv, xs[j])
                ctx = [ctx[t] + att[j] * vj[t] for t in range(self.d)]
            o = _mat_vec(self.Wo, ctx)
            ffn = [math.tanh(sum(self.ffW[t][k] * (o[k] + xs[i][k]) for k in range(self.d)) + self.ffb[t])
                   for t in range(self.d)]
            hs.append(_add(o, ffn))
        # 平均池化
        out = _zeros(self.d)
        for h in hs:
            out = [out[t] + h[t] for t in range(self.d)]
        return [x / len(hs) for x in out]

    def set_rng(self, rng):
        self._rng_obj = rng


# ===========================================================================
# 检测器
# ===========================================================================
class SeqAnomalyDetector:
    def __init__(self):
        self.d = max(8, int(configs.SEQ_ANOMALY_HIDDEN))
        self.window = max(2, int(configs.SEQ_ANOMALY_WINDOW))
        self.model_kind = (configs.SEQ_ANOMALY_MODEL or "gru").lower()
        self.anomaly_factor = float(getattr(configs, "SEQ_ANOMALY_ANOMALY_FACTOR", 2.5))
        self.min_samples = max(1, int(configs.SEQ_ANOMALY_MIN_SAMPLES))
        self.lr = 0.05

        self._rng = self._make_rng()

        # ---- 计算后端自动选择（依赖+系统配置+工作负载）----
        self.backend_info = _select_backend()
        self.backend = self.backend_info["backend"]
        if self.backend == "torch":
            self.gru = _TorchGRU(self.d, self._rng)
            self.tf = _TorchTransformer(self.d, 2, self._rng)
        elif self.backend == "numpy":
            self.gru = _NumpyGRU(self.d, self._rng)
            self.tf = _NumpyTransformer(self.d, 2, self._rng)
        else:
            self.gru = _TinyGRU(self.d, self._rng)
            self.tf = _TinyTransformer(self.d, 2, self._rng)

        # 读出层向量化缓存（numpy/torch 后端用；python 后端忽略）
        self._ro_dirty = True
        self._ro_ids = []
        self._ro_W = None
        self._ro_b = None
        self.np = None
        self.torch = None
        if self.backend == "numpy":
            try:
                import numpy as _np
                self.np = _np
            except Exception:
                self.backend = "python"
        elif self.backend == "torch":
            try:
                import torch as _torch
                self.torch = _torch
            except Exception:
                self.backend = "python"

        # 词表（token -> id, id -> token）
        self.token2id = {}
        self.id2token = {}
        self._next_id = 0

        # 在线训练读出层: token id -> (w[d], b)
        self.readout_w = {}
        self.readout_b = {}

        # 每个 tracking-key 的状态
        self.seq = {}            # key -> [token_id, ...] 近期窗口
        self.ema = {}             # key -> surprise 基线
        self.count = {}           # key -> 已观察样本数
        self.recent_scores = {}  # key -> 最近几次 surprise（用于报告）

        self.lock = threading.Lock()
        self._load_snapshot()

    @staticmethod
    def _make_rng():
        try:
            return __import__("random").Random(0xC0FFEE)
        except Exception:
            return __import__("random").Random()

    # ---------- 词表 ----------
    def _tok_id(self, token):
        tid = self.token2id.get(token)
        if tid is None:
            tid = self._next_id
            self._next_id += 1
            self.token2id[token] = tid
            self.id2token[tid] = token
            self.readout_w[tid] = _zeros(self.d)
            self.readout_b[tid] = 0.0
            self._ro_dirty = True
        return tid

    # ---------- 表征 ----------
    def _hidden(self, seq_ids):
        h1 = self.gru.forward(seq_ids, self._rng)
        if self.model_kind == "transformer":
            return self.tf.forward(seq_ids, self._rng)
        if self.model_kind == "both":
            h2 = self.tf.forward(seq_ids, self._rng)
            return [(h1[i] + h2[i]) / 2.0 for i in range(self.d)]
        return h1

    # ---------- 预测分布 ----------
    def _predict(self, seq_ids):
        """返回 (token_id -> prob) 与上下文向量 h。"""
        h = self._hidden(seq_ids)
        if self.backend == "python":
            logits = {}
            for tid in self.readout_w:
                logits[tid] = _dot(self.readout_w[tid], h) + self.readout_b[tid]
            probs = _softmax(list(logits.values()))
            return dict(zip(logits.keys(), probs)), h

        # numpy / torch：读出层堆叠矩阵一次算全词表 logits
        np = self.np if self.backend == "numpy" else None
        th = self.torch if self.backend == "torch" else None
        if self._ro_dirty or self._ro_W is None:
            ids = sorted(self.readout_w)
            if np is not None:
                self._ro_W = np.array([self.readout_w[t] for t in ids], dtype=np.float64) if ids \
                    else np.zeros((0, self.d), dtype=np.float64)
                self._ro_b = np.array([self.readout_b[t] for t in ids], dtype=np.float64) if ids \
                    else np.zeros((0,), dtype=np.float64)
            else:
                self._ro_W = th.tensor([self.readout_w[t] for t in ids], dtype=th.float64) if ids \
                    else th.zeros((0, self.d), dtype=th.float64)
                self._ro_b = th.tensor([self.readout_b[t] for t in ids], dtype=th.float64) if ids \
                    else th.zeros((0,), dtype=th.float64)
            self._ro_ids = ids
            self._ro_dirty = False
        if not self._ro_ids:
            return {}, h
        if np is not None:
            logits = self._ro_W @ np.asarray(h, dtype=np.float64) + self._ro_b
            logits = logits - logits.max()
            e = np.exp(logits)
            probs = e / (e.sum() or 1e-12)
        else:
            logits = self._ro_W @ th.tensor(h, dtype=th.float64) + self._ro_b
            logits = logits - logits.max()
            e = torch_exp = th.exp(logits)
            probs = e / (e.sum() or 1e-12)
        return {tid: float(p) for tid, p in zip(self._ro_ids, probs)}, h

    # ---------- 在线训练一步 ----------
    def _train_step(self, target_id, h):
        probs, _ = self._predict(self._last_seq_ids_for_train)
        # 对目标 token 做 SGD（仅更新目标读出向量，避免全词表更新导致基线漂移过快）
        p_target = probs.get(target_id, 1e-9)
        g = (p_target - 1.0) * self.lr  # cross-entropy 对 logit 的梯度沿目标方向
        w = self.readout_w[target_id]
        for i in range(self.d):
            w[i] -= g * h[i]
        self.readout_b[target_id] -= g
        # 同步向量化缓存的目标行（失败则置脏，下次预测时整体重建）
        try:
            if self.backend != "python" and self._ro_W is not None and not self._ro_dirty:
                idx = self._ro_ids.index(target_id)
                if self.backend == "numpy":
                    np = self.np
                    self._ro_W[idx] -= g * np.asarray(h, dtype=np.float64)
                    self._ro_b[idx] -= g
                else:
                    th = self.torch
                    self._ro_W[idx] -= g * th.tensor(h, dtype=th.float64)
                    self._ro_b[idx] -= g
        except Exception:
            self._ro_dirty = True

    # ---------- 主接口 ----------
    def record_and_score(self, tracking_key: str, token: str):
        """记录一次访问并返回异常评分。

        返回 dict:
          token, surprise, baseline, anomaly(bool), score(0~1 越高越异常),
          samples, model, predicted_top
        """
        with self.lock:
            tid = self._tok_id(token)
            hist = self.seq.get(tracking_key, [])
            ctx_ids = hist[-(self.window - 1):]  # 不含当前
            self._last_seq_ids_for_train = ctx_ids

            surprise = 0.0
            predicted_top = None
            if ctx_ids:
                probs, h = self._predict(ctx_ids)
                p = max(probs.get(tid, 0.0), 1e-9)
                surprise = -math.log(p)
                # 在线训练（用真实 token 更新读出层）
                try:
                    self._train_step(tid, h)
                except Exception as e:
                    logger.debug(f"seq train step failed: {e}")
                # 预测 top
                best, bestp = None, -1.0
                for k, v in probs.items():
                    if v > bestp:
                        bestp, best = v, k
                predicted_top = self.id2token.get(best)
            else:
                # 序列太短，无法预测，仅记录
                pass

            # 更新基线（EMA）
            base = self.ema.get(tracking_key, None)
            if base is None:
                base = surprise
            else:
                base = 0.9 * base + 0.1 * surprise
            self.ema[tracking_key] = base

            n = self.count.get(tracking_key, 0) + 1
            self.count[tracking_key] = n

            # 异常判定
            anomaly = False
            score = 0.0
            if n >= self.min_samples and surprise > 0:
                if surprise > base * self.anomaly_factor and surprise > 1.0:
                    anomaly = True
                    score = min(1.0, (surprise - base) / max(base, 1e-6))
            elif n >= self.min_samples:
                # surprise==0 说明完全可预测，正常
                pass

            # 维护近期窗口
            hist.append(tid)
            if len(hist) > self.window:
                hist = hist[-self.window:]
            self.seq[tracking_key] = hist

            rc = self.recent_scores.setdefault(tracking_key, [])
            rc.append(round(surprise, 3))
            if len(rc) > 10:
                rc.pop(0)

            if anomaly:
                try:
                    self._save_snapshot()
                except Exception:
                    pass

            return {
                "token": token,
                "surprise": round(surprise, 4),
                "baseline": round(base, 4),
                "anomaly": anomaly,
                "score": round(score, 4),
                "samples": n,
                "model": self.model_kind,
                "predicted_top": predicted_top,
                "vocab_size": len(self.token2id),
            }

    # ---------- 快照持久化（可选）----------
    def _snapshot_path(self):
        p = getattr(configs, "SEQ_ANOMALY_PERSIST_PATH", "") or ""
        if not p:
            return ""
        # 支持 <data> 占位
        if p.startswith("<data>"):
            try:
                from .db import DB_PATH
                p = os.path.join(os.path.dirname(DB_PATH), p[len("<data>"):].lstrip("/\\"))
            except Exception:
                return ""
        return p

    def _save_snapshot(self):
        if not getattr(configs, "SEQ_ANOMALY_PERSIST", True):
            return
        path = self._snapshot_path()
        if not path:
            return
        try:
            snap = {
                "token2id": self.token2id,
                "id2token": {str(k): v for k, v in self.id2token.items()},
                "readout_w": {str(k): v for k, v in self.readout_w.items()},
                "readout_b": {str(k): v for k, v in self.readout_b.items()},
                "ema": self.ema,
                "count": self.count,
            }
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snap, f)
            os.replace(tmp, path)
        except Exception as e:
            logger.debug(f"seq snapshot save failed: {e}")

    def _load_snapshot(self):
        path = self._snapshot_path()
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                snap = json.load(f)
            self.token2id = snap.get("token2id", {})
            self.id2token = {int(k): v for k, v in snap.get("id2token", {}).items()}
            self.readout_w = {int(k): v for k, v in snap.get("readout_w", {}).items()}
            self.readout_b = {int(k): v for k, v in snap.get("readout_b", {}).items()}
            self.ema = snap.get("ema", {})
            self.count = snap.get("count", {})
            self._next_id = (max(self.id2token.keys()) + 1) if self.id2token else 0
            logger.info(f"序列异常检测器已加载快照（词表 {len(self.token2id)}）")
        except Exception as e:
            logger.warning(f"seq snapshot load failed: {e}")

    # ---------- 查询 ----------
    def status(self) -> dict:
        with self.lock:
            top = sorted(self.count.items(), key=lambda kv: kv[1], reverse=True)[:10]
            flagged = [k for k, v in self.ema.items()]
            return {
                "enabled": getattr(configs, "SEQ_ANOMALY_ENABLED", True),
                "model": self.model_kind,
                "backend": self.backend,
                "backend_reason": self.backend_info.get("reason", ""),
                "numpy_version": self.backend_info.get("numpy_version"),
                "torch_version": self.backend_info.get("torch_version"),
                "hidden": self.d,
                "window": self.window,
                "anomaly_factor": self.anomaly_factor,
                "min_samples": self.min_samples,
                "vocab_size": len(self.token2id),
                "tracked_keys": len(self.seq),
                "tracked_top": [{"key": k, "samples": self.count.get(k, 0),
                                 "baseline": round(self.ema.get(k, 0.0), 3)}
                                for k, _ in top],
                "flagged_keys": len(flagged),
            }

    def reset(self):
        with self.lock:
            self.seq.clear()
            self.ema.clear()
            self.count.clear()
            self.recent_scores.clear()


# ===========================================================================
# 模块级单例
# ===========================================================================
_detector = None
_detector_lock = threading.Lock()


def get_detector() -> SeqAnomalyDetector:
    global _detector
    if _detector is None:
        with _detector_lock:
            if _detector is None:
                _detector = SeqAnomalyDetector()
    return _detector


def record_and_score(tracking_key: str, method: str, path: str) -> dict:
    """便捷接口：归一化端点并打分。"""
    if not getattr(configs, "SEQ_ANOMALY_ENABLED", True):
        return {"enabled": False}
    token = normalize_endpoint(method, path)
    try:
        return get_detector().record_and_score(tracking_key, token)
    except Exception as e:
        logger.error(f"seq_anomaly record_and_score failed: {e}")
        return {"error": str(e)}


def status() -> dict:
    return get_detector().status()
