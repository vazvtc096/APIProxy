"""令牌级管控：每个 API Key 可独立设置额度 / 过期时间 / 模型白名单 / IP 白名单。

对齐 NewAPI 的 token 管理能力：
- label          备注名
- expires_at     过期时间（NULL = 永不过期）
- quota          额度上限（NULL = 不限；used 累计已消耗）
- allowed_models 模型白名单（逗号分隔，支持「前缀*」通配；空 = 不限，跟随用户组）
- ip_whitelist   IP 白名单（逗号分隔，支持 CIDR；空 = 不限）
- is_active      停用开关（0 = 已停用）

策略在 /v1/* 鉴权链路强制执行；用量在计费落点累计（used 可能因单次请求
略超 quota——与 NewAPI 行为一致，超限在下次请求时拦截）。

限速（对齐 NewAPI token 限速）：
- rpm_limit  每分钟请求数上限（0 = 不限），请求入口固定窗口计数（cache_store）
- tpm_limit  每分钟字符量上限（0 = 不限），与全站计费/统计口径一致（1 token≈3 字符）；
              请求前预检当前窗口累计，响应后在计费落点把输入+输出字符计入窗口
"""
import datetime
import fnmatch
import ipaddress
import logging

from . import db


def _get_conn():
    return db.get_conn()


_POLICY_COLUMNS = (
    ("label", "TEXT DEFAULT ''"),
    ("expires_at", "TIMESTAMP"),
    ("quota", "REAL"),
    ("used", "REAL DEFAULT 0"),
    ("allowed_models", "TEXT DEFAULT ''"),
    ("ip_whitelist", "TEXT DEFAULT ''"),
    ("is_active", "INTEGER DEFAULT 1"),
    ("rpm_limit", "INTEGER DEFAULT 0"),
    ("tpm_limit", "INTEGER DEFAULT 0"),
)


def ensure_policy_columns():
    """幂等补列（PG 抛 DuplicateColumn / SQLite 抛 OperationalError 均吞掉）"""
    conn = _get_conn()
    from . import db as _db
    if _db.is_postgres():
        conn.set_autocommit(True)
    cur = conn.cursor()
    for col, defn in _POLICY_COLUMNS:
        try:
            cur.execute(f"ALTER TABLE apikeys ADD COLUMN {col} {defn}")
        except Exception:
            pass
    try:
        conn.commit()
    except Exception:
        pass
    conn.close()


ensure_policy_columns()


def _norm_expires(val):
    """规范化过期时间为 ISO 字符串（入参支持 'YYYY-MM-DD HH:MM:SS' / ISO / None / ''）"""
    if val is None or str(val).strip() == '':
        return None
    s = str(val).strip().replace('T', ' ')
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        raise ValueError(f"invalid expires_at: {val!r} (expect YYYY-MM-DD[ HH:MM:SS])")
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def _ip_in_list(ip: str, whitelist: str) -> bool:
    """IP 是否命中白名单（支持 CIDR；空名单 = 不限）"""
    entries = [x.strip() for x in (whitelist or '').split(',') if x.strip()]
    if not entries:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for e in entries:
        try:
            if '/' in e:
                if addr in ipaddress.ip_network(e, strict=False):
                    return True
            elif addr == ipaddress.ip_address(e):
                return True
        except ValueError:
            continue
    return False


def model_allowed(model: str, allowed_models: str) -> bool:
    """模型是否命中白名单（支持 fnmatch 通配，如 deepseek-*；空 = 不限）"""
    pats = [x.strip() for x in (allowed_models or '').split(',') if x.strip()]
    if not pats:
        return True
    return any(fnmatch.fnmatchcase(model or '', p) for p in pats)


def get_policy(key_hash: str) -> dict | None:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, apikey_hash, owner_name, label, expires_at, quota, used, "
            "allowed_models, ip_whitelist, is_active, rpm_limit, tpm_limit, "
            "created_at, last_used_at "
            "FROM apikeys WHERE apikey_hash = ?", (key_hash,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ---------- 令牌级 RPM/TPM 计数（cache_store 固定窗口，多实例共享） ----------
_RPM_WINDOW = 60   # 秒
_TPM_WINDOW = 60   # 秒


def _window_key(kind: str, key_hash: str) -> tuple[str, int]:
    """返回 (计数键, 距窗口重置秒数)。窗口按自然分钟对齐。"""
    import time as _time
    now = _time.time()
    win = int(now // 60)
    return f"tok:rl:{kind}:{key_hash}:{win}", 60 - int(now % 60) + 1


def _rl_cache():
    from . import cache_store
    return cache_store.get_cache()


def _check_rpm(key_hash: str, rpm_limit: int) -> tuple[bool, str]:
    """请求数固定窗口计数。返回 (ok, reason)。"""
    key, retry_in = _window_key('rpm', key_hash)
    cache = _rl_cache()
    try:
        cnt = int(cache.incr(key) or 0)
        cache.expire(key, 130)  # 幂等续期，防首写 TTL 丢失导致键永生
    except Exception as e:
        logging.warning(f"token rpm counter failed (fail-open): {e}")
        return True, ''
    if rpm_limit and cnt > rpm_limit:
        return False, (f"token rate limit: {rpm_limit} requests/min exceeded, "
                       f"retry in {retry_in}s")
    return True, ''


def _check_tpm(key_hash: str, tpm_limit: int) -> tuple[bool, str]:
    """字符量窗口预检（只读；响应后由 accrue_tpm 计入）。返回 (ok, reason)。"""
    if not tpm_limit:
        return True, ''
    key, retry_in = _window_key('tpm', key_hash)
    try:
        val = _rl_cache().get(key)
        cnt = int(val) if val is not None else 0
    except Exception as e:
        logging.warning(f"token tpm counter read failed (fail-open): {e}")
        return True, ''
    if cnt >= tpm_limit:
        return False, (f"token rate limit: {tpm_limit} chars/min exceeded, "
                       f"retry in {retry_in}s")
    return True, ''


def accrue_tpm(key_hash: str, chars: int):
    """把一次请求消耗的字符数计入当前 TPM 窗口（key_hash 为空则跳过——OAuth key 无令牌策略）。

    用读-改-写而非逐字符 incr（单次请求可能几千字符）；并发下可能轻微低估，
    与软限制语义一致（同 NewAPI：超限在下次请求拦截）。
    """
    if not key_hash or not chars:
        return
    try:
        key, _ = _window_key('tpm', key_hash)
        cache = _rl_cache()
        val = cache.get(key)
        cur = int(val) if val is not None else 0
        cache.set(key, cur + int(chars), 130)
    except Exception as e:
        logging.warning(f"token tpm accrue failed: {e}")


def check_policy(key_hash: str, ip: str, model: str = None) -> tuple:
    """校验令牌策略。返回 (ok, reason)；reason 为空串表示通过。"""
    p = get_policy(key_hash)
    if p is None:
        return False, 'token not found'
    if not p.get('is_active', 1):
        return False, 'token disabled'
    exp = p.get('expires_at')
    if exp:
        if isinstance(exp, str):
            try:
                exp_dt = datetime.datetime.fromisoformat(exp.replace('T', ' '))
            except ValueError:
                exp_dt = None
        else:
            exp_dt = exp
        if exp_dt is not None and datetime.datetime.now() > exp_dt:
            return False, f'token expired at {exp}'
    if not _ip_in_list(ip or '', p.get('ip_whitelist') or ''):
        return False, f'client ip {ip} not in token ip whitelist'
    if model is not None and not model_allowed(model, p.get('allowed_models') or ''):
        return False, f"model '{model}' not allowed by token policy"
    quota = p.get('quota')
    if quota is not None and (p.get('used') or 0.0) >= float(quota):
        return False, f'token quota exhausted ({p.get("used"):.4f}/{float(quota):.4f})'
    # 令牌级限速（rpm_limit / tpm_limit，0 = 不限）
    rpm = int(p.get('rpm_limit') or 0)
    tpm = int(p.get('tpm_limit') or 0)
    if rpm or tpm:
        if tpm:
            ok, reason = _check_tpm(key_hash, tpm)
            if not ok:
                return False, reason
        if rpm:
            ok, reason = _check_rpm(key_hash, rpm)
            if not ok:
                return False, reason
    return True, ''


def accrue_usage(key_hash: str, cost: float):
    """累计令牌用量（与余额扣费解耦：令牌额度是独立于余额的第二层管控）"""
    if not key_hash or not cost:
        return
    try:
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE apikeys SET used = COALESCE(used, 0) + ? WHERE apikey_hash = ?",
                (float(cost), key_hash))
            conn.commit()
    except Exception as e:
        logging.error(f"tokenpolicy.accrue_usage failed: {e}")


def list_policies(owner: str = None) -> list:
    """列出令牌（owner=None 时列出全部——仅管理端使用）"""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        if owner is None:
            cur.execute(
                "SELECT id, apikey_hash, owner_name, label, expires_at, quota, used, "
                "allowed_models, ip_whitelist, is_active, rpm_limit, tpm_limit, "
                "created_at, last_used_at "
                "FROM apikeys ORDER BY id")
        else:
            cur.execute(
                "SELECT id, apikey_hash, owner_name, label, expires_at, quota, used, "
                "allowed_models, ip_whitelist, is_active, rpm_limit, tpm_limit, "
                "created_at, last_used_at "
                "FROM apikeys WHERE owner_name = ? ORDER BY id", (owner,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            d = dict(r)
            # 只暴露哈希前 12 位用于前端定位，不泄露完整哈希
            d['key_hint'] = (d.pop('apikey_hash') or '')[:12]
            out.append(d)
        return out
    finally:
        conn.close()


def set_policy(key_id: int, owner: str = None, is_admin: bool = False, **fields) -> tuple:
    """更新令牌策略。返回 (ok, error)。owner 非 None 时校验归属。"""
    allowed_fields = {'label', 'expires_at', 'quota', 'allowed_models',
                      'ip_whitelist', 'is_active', 'rpm_limit', 'tpm_limit'}
    sets, args = [], []
    for k, v in fields.items():
        if k not in allowed_fields or v is None:
            continue
        if k == 'expires_at':
            try:
                v = _norm_expires(v)
            except ValueError as e:
                return False, str(e)
        elif k == 'quota':
            try:
                v = None if float(v) <= 0 else float(v)
            except (TypeError, ValueError):
                return False, 'quota must be a number'
        elif k == 'is_active':
            v = 1 if v in (1, True, '1', 'true', 'True') else 0
        elif k in ('rpm_limit', 'tpm_limit'):
            try:
                v = max(0, int(float(v)))
            except (TypeError, ValueError):
                return False, f'{k} must be a non-negative integer'
        elif k in ('label', 'allowed_models', 'ip_whitelist'):
            v = str(v)[:500]
        sets.append(f"{k} = ?")
        args.append(v)
    if not sets:
        return False, 'no valid fields to update'
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            if owner is not None and not is_admin:
                cur.execute(f"UPDATE apikeys SET {', '.join(sets)} WHERE id = ? AND owner_name = ?",
                            (*args, key_id, owner))
            else:
                cur.execute(f"UPDATE apikeys SET {', '.join(sets)} WHERE id = ?",
                            (*args, key_id))
            if cur.rowcount == 0:
                conn.rollback()
                return False, 'token not found or not owned by you'
            conn.commit()
        return True, ''
    finally:
        conn.close()
