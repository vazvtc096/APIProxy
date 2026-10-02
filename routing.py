"""路由层：模型映射 + 上游健康状态 + 负载均衡/故障转移。

- 模型映射（DB 表 model_mappings）：请求模型【A】→ 上游【B】的【C】模型。
  B 为空 = 任意可用上游；B 多个 = 候选集合（数量相当于正则中的 *，按优先级+健康度挑选）。
  pattern 支持精确名与 '前缀*' 通配（'*' 结尾），先精确后通配，按 id 稳定排序。
- 健康状态（内存）：运行时错误计数 + 冷却窗口（连续失败进入冷却，冷却期内
  负载均衡把该上游排到最后/跳过），由定时探测与真实请求共同更新。
- 负载均衡：优先级（priority 越小越优先）为第一序，健康度为第一优先约束——
  「代价（失败概率）> 优先级收益」时路由到下一个候选，并在链上做逐个故障转移。
- 定时探测（可关闭）：每 interval 秒对每个启用上游发一次 max_tokens≤100 的
  最低成本请求，失败即记入健康状态，避免用户请求时才撞上坏上游。
"""
import asyncio
import logging
import time

from . import db

# ---------- 健康状态（进程内） ----------
# name -> {'consecutive': n, 'cooldown_until': ts, 'last_ok': ts, 'last_fail': ts,
#          'total': n, 'fail': n, 'latency_ema': ms}
_HEALTH: dict = {}
_FAIL_THRESHOLD = 2        # 连续失败 N 次进入冷却
_COOLDOWN_SECONDS = 60     # 冷却窗口：期内负载均衡视为不健康
_PROBE_LATENCY_EMA_ALPHA = 0.3


def _state(name: str) -> dict:
    if name not in _HEALTH:
        _HEALTH[name] = {'consecutive': 0, 'cooldown_until': 0.0,
                         'last_ok': 0.0, 'last_fail': 0.0,
                         'total': 0, 'fail': 0, 'latency_ema': 0.0}
    return _HEALTH[name]


def record_success(name: str, latency_ms: float):
    st = _state(name)
    recovered = st['cooldown_until'] > time.time()   # 曾处于冷却 = 刚恢复
    st['consecutive'] = 0
    st['cooldown_until'] = 0.0
    st['last_ok'] = time.time()
    st['total'] += 1
    st['latency_ema'] = (latency_ms if not st['latency_ema']
                         else _PROBE_LATENCY_EMA_ALPHA * latency_ms
                         + (1 - _PROBE_LATENCY_EMA_ALPHA) * st['latency_ema'])
    if recovered:
        try:
            from . import notify
            notify.notify('上游恢复', f"上游 {name} 已恢复正常")
        except Exception:
            pass


def record_failure(name: str):
    st = _state(name)
    was_healthy = time.time() >= st['cooldown_until']
    st['consecutive'] += 1
    st['last_fail'] = time.time()
    st['total'] += 1
    st['fail'] += 1
    if st['consecutive'] >= _FAIL_THRESHOLD:
        st['cooldown_until'] = time.time() + _COOLDOWN_SECONDS
        logging.warning(f"upstream '{name}' unhealthy: {st['consecutive']} consecutive failures, "
                        f"cooldown {_COOLDOWN_SECONDS}s")
        if was_healthy:   # 仅在健康→故障的翻转点推送，冷却期内重复失败不刷屏
            try:
                from . import notify
                notify.notify('上游故障',
                              f"上游 {name} 连续 {st['consecutive']} 次失败，"
                              f"已摘除负载均衡 {_COOLDOWN_SECONDS} 秒")
            except Exception:
                pass


def is_healthy(name: str) -> bool:
    st = _HEALTH.get(name)
    if not st:
        return True
    return time.time() >= st['cooldown_until']


def health_snapshot() -> dict:
    """供管理端查看的健康状态只读快照"""
    now = time.time()
    out = {}
    for name, st in _HEALTH.items():
        out[name] = {**st, 'healthy': now >= st['cooldown_until'],
                     'cooldown_remaining': max(0.0, st['cooldown_until'] - now)}
    return out


# ---------- 模型映射 ----------
_MAP_CACHE = {'rows': None, 'ts': 0.0}
_MAP_TTL = 30.0


def _load_mappings() -> list:
    """从 DB 读映射表（30s 缓存）。表不存在返回 []。"""
    now = time.time()
    if _MAP_CACHE['rows'] is not None and now - _MAP_CACHE['ts'] < _MAP_TTL:
        return _MAP_CACHE['rows']
    rows = []
    try:
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, pattern, upstreams, target_model, enabled "
                        "FROM model_mappings WHERE enabled = 1 ORDER BY id")
            for r in cur.fetchall():
                d = dict(r) if not isinstance(r, dict) else r
                ups = [u.strip() for u in (d.get('upstreams') or '').split(',') if u.strip()]
                rows.append({'pattern': d['pattern'], 'upstreams': ups,
                             'target': d['target_model']})
        finally:
            conn.close()
    except Exception as e:
        logging.error(f"load model_mappings failed: {e}")
        rows = []
    _MAP_CACHE['rows'] = rows
    _MAP_CACHE['ts'] = now
    return rows


def invalidate_mapping_cache():
    _MAP_CACHE['rows'] = None
    _MAP_CACHE['ts'] = 0.0


def map_model(model: str):
    """返回 (目标模型, 允许的上游名列表或 None=任意)。无匹配映射时原样返回。"""
    for m in _load_mappings():
        p = m['pattern']
        if p.endswith('*'):
            if model.startswith(p[:-1]):
                return m['target'], (m['upstreams'] or None)
        elif p == model:
            return m['target'], (m['upstreams'] or None)
    return model, None


def build_chain(model: str, requested_name: str = None) -> list:
    """构造按尝试顺序排列的候选链 [(client, upstream_name, 实际请求模型), ...]。

    顺序 = 健康优先 + 优先级次之；映射限定的上游集合之外的候选被剔除。
    全部不健康时仍返回优先级顺序的完整链（尽力而为，冷却只是降权不是拉黑）。
    """
    from . import upstreams
    target, allowed = map_model(model)
    cands = upstreams.iter_candidates(target, requested_name)
    if allowed:
        cands = [c for c in cands if c[1] in allowed]
    healthy = [c for c in cands if is_healthy(c[1])]
    ordered = healthy + [c for c in cands if c not in healthy]
    return [(client, name, target) for client, name, _prio in ordered]


# ---------- 定时健康探测（可关闭） ----------
_PROBER_THREAD = None


async def _probe_once() -> int:
    """对所有启用上游各发一次最低成本探测，返回探测的上游数。

    模型选择：配置 probe_model 指定；否则取该上游模型目录里的第一个
    （配合 max_tokens=1 + 短 prompt，成本最小化）。目录未知时跳过。
    """
    from . import upstreams, configs
    hc = getattr(configs, 'UPSTREAM_HEALTH', {}) or {}
    fixed_model = hc.get('probe_model')
    max_tokens = int(hc.get('max_tokens', 1))
    n = 0
    for u in list(configs.UPSTREAMS):
        if not u.get('enabled'):
            continue
        name = u['name']
        client = upstreams.get_client(name)
        if client is None:
            continue
        model = fixed_model
        if not model:
            cat = upstreams.upstream_models(name)
            model = sorted(cat)[0] if cat else None
        if not model:
            continue  # 目录未知：不盲猜（打错模型名会白白污染健康状态）
        t0 = time.perf_counter()
        try:
            await asyncio.wait_for(
                client.chat.completions.create(
                    model=model,
                    messages=[{'role': 'user', 'content': 'ping'}],
                    max_tokens=max_tokens,
                    timeout=30,
                ), timeout=45)
            record_success(name, (time.perf_counter() - t0) * 1000)
        except Exception as e:
            record_failure(name)
            logging.warning(f"health probe {name} ({model}) failed: {e}")
        n += 1
    return n


async def _prober_loop():
    from . import configs
    while True:
        hc = getattr(configs, 'UPSTREAM_HEALTH', {}) or {}
        if not hc.get('enabled'):
            await asyncio.sleep(30)  # 关闭状态下低频空转，热开启无需重启
            continue
        interval = max(30, int(hc.get('interval_seconds', 300)))
        try:
            await _probe_once()
        except Exception as e:
            logging.error(f"health probe round failed: {e}")
        await asyncio.sleep(interval)


def start_health_prober():
    """启动定时探测后台线程（独立事件循环，幂等；可在无 asyncio loop 的启动期调用）"""
    import threading
    global _PROBER_THREAD
    if _PROBER_THREAD is not None and _PROBER_THREAD.is_alive():
        return

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_prober_loop())
        except Exception as e:
            logging.error(f"health prober loop exited: {e}")

    _PROBER_THREAD = threading.Thread(target=_run, daemon=True, name='upstream-health-prober')
    _PROBER_THREAD.start()
    logging.info("upstream health prober started")
