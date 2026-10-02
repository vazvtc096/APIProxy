"""运维设置（管理端 WebUI 可调）：余额预警 + 数据备份 + 日志保留。

持久化在 DB 的 app_settings 表（key='ops_settings'，值为 JSON blob），
config.yaml 里的 balance_alert / db_backup / retention 段作为首次默认值——
DB 覆盖优先。保存即热生效（直接原地更新 configs.BALANCE_ALERT / DB_BACKUP /
RETENTION 字典，各消费方每次调用都重读，无需重启）。

表结构（幂等自建，不走 Alembic——与 pricing.reload_pricing_from_db
同样的"表缺失容忍"策略，SQLite/PG 双兼容）：
    CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""
import json
import logging

from . import configs

logger = logging.getLogger(__name__)

_KEY = 'ops_settings'

# section -> (字段 -> (类型, 范围))
# 类型: bool / int / float / str / range([lo, hi] 数值区间)
_SCHEMA = {
    'balance_alert': {
        'enabled': ('bool', None),
        'threshold': ('float', (0, 100000)),
        'cooldown_hours': ('int', (1, 720)),
        'email': ('bool', None),
    },
    'db_backup': {
        'enabled': ('bool', None),
        'hour': ('int', (0, 23)),
        'keep_days': ('int', (1, 365)),
    },
    # dir 不开放 WebUI：相对路径校验麻烦且收益低，保持 config.yaml 管理
    'retention': {
        'enabled': ('bool', None),
        'hour': ('int', (0, 23)),
        'usage_days': ('int', (0, 3650)),
        'audit_days': ('int', (0, 3650)),
        'batch': ('int', (100, 50000)),
    },
    'upstream_health': {
        'enabled': ('bool', None),
        'interval_seconds': ('int', (30, 86400)),
        'max_tokens': ('int', (1, 100)),
        'probe_model': ('str', (0, 200)),
    },
    'param_limits': {
        'enabled': ('bool', None),
        'max_tokens_cap': ('int', (0, 1000000)),
        'temperature_range': ('range', (-2, 10)),
        'top_p_range': ('range', (0, 5)),
    },
    'smtp': {
        'server': ('str', (0, 200)),
        'port': ('int', (1, 65535)),
        'user': ('str', (0, 200)),
        'pass': ('str', (0, 200)),
        'from': ('str', (0, 200)),
    },
    'napcat': {
        'enabled': ('bool', None),
        'base_url': ('str', (0, 200)),
        'token': ('str', (0, 200)),
        'user_ids': ('str', (0, 500)),    # 逗号分隔 QQ 号
        'group_ids': ('str', (0, 500)),   # 逗号分隔群号
    },
    'token_billing': {
        'enabled': ('bool', None),
        'cache_hit_ratio': ('float', (0.0, 1.0)),  # 缓存命中输入价/未命中价
    },
}

# section -> configs 运行时字典属性名（smtp 特例：SMTP_SETTINGS）
_SECTION_TARGET = {
    'balance_alert': 'BALANCE_ALERT',
    'db_backup': 'DB_BACKUP',
    'retention': 'RETENTION',
    'upstream_health': 'UPSTREAM_HEALTH',
    'param_limits': 'PARAM_LIMITS',
    'smtp': 'SMTP_SETTINGS',
    'napcat': 'NAPCAT',
    'token_billing': 'TOKEN_BILLING',
}

_ensured = False


def ensure_table():
    """幂等建表（进程内只执行一次）。"""
    global _ensured
    if _ensured:
        return
    from . import db
    conn = db.get_conn()
    try:
        conn.cursor().execute(
            'CREATE TABLE IF NOT EXISTS app_settings ('
            'key TEXT PRIMARY KEY, value TEXT NOT NULL, '
            'updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        conn.commit()
    finally:
        conn.close()
    _ensured = True


def get_overrides() -> dict:
    """读取 DB 覆盖值（无则 {}）。表缺失/异常时返回 {} 不抛。"""
    try:
        ensure_table()
        from . import db
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute('SELECT value FROM app_settings WHERE key = ?', (_KEY,))
            row = cur.fetchone()
        finally:
            conn.close()
        if not row:
            return {}
        raw = row[0] if isinstance(row, (tuple, list)) else row['value']
        d = json.loads(raw)
        return d if isinstance(d, dict) else {}
    except Exception as e:
        logger.warning(f"ops_settings read failed: {e}")
        return {}


def apply_overrides():
    """启动时把 DB 覆盖值原地并入 configs（WebUI 保存过的值优先于 config.yaml）。"""
    ov = get_overrides()
    for section in _SECTION_TARGET:
        patch = ov.get(section)
        if not isinstance(patch, dict) or not patch:
            continue
        target = getattr(configs, _SECTION_TARGET[section], None)
        if isinstance(target, dict):
            target.update(patch)
            logger.info(f"ops_settings applied override: {section} -> "
                        f"{_mask(section, patch)}")


def _mask(section: str, values: dict) -> dict:
    """日志/日志脱敏：smtp.pass / napcat.token 等敏感字段不落明文。"""
    out = dict(values)
    if section == 'smtp' and 'pass' in out:
        out['pass'] = '[redacted]' if out['pass'] else ''
    if section == 'napcat' and 'token' in out:
        out['token'] = '[redacted]' if out['token'] else ''
    return out


def _coerce(typ, v, rng):
    """按 schema 类型转换并校验单值，失败抛 ValueError/TypeError。"""
    if typ == 'bool':
        if isinstance(v, str):
            return v.lower() in ('1', 'true', 'yes', 'on')
        return bool(v)
    if typ == 'int':
        iv = int(float(v))
        if rng is not None and not (rng[0] <= iv <= rng[1]):
            raise ValueError(f'out of range {rng[0]}-{rng[1]}')
        return iv
    if typ == 'float':
        fv = float(v)
        if rng is not None and not (rng[0] <= fv <= rng[1]):
            raise ValueError(f'out of range {rng[0]}-{rng[1]}')
        return fv
    if typ == 'str':
        sv = str(v)
        limit = rng[1] if rng else 200
        if len(sv.strip()) > limit:
            raise ValueError(f'length out of range 0-{limit}')
        return sv.strip()[:limit]
    if typ == 'range':
        if not isinstance(v, (list, tuple)) or len(v) != 2:
            raise ValueError('must be [lo, hi]')
        lo, hi = float(v[0]), float(v[1])
        if lo > hi:
            raise ValueError('lo > hi')
        if rng is not None and not (rng[0] <= lo and hi <= rng[1]):
            raise ValueError(f'out of range [{rng[0]}, {rng[1]}]')
        return [lo, hi]
    raise ValueError(f'unknown type {typ}')


def save(section: str, values: dict) -> tuple[bool, str]:
    """校验并保存一个 section，热生效。返回 (ok, error)。"""
    if section not in _SCHEMA:
        return False, f'unknown section: {section}'
    if not isinstance(values, dict):
        return False, 'values must be an object'
    schema = _SCHEMA[section]
    patch = {}
    for field, (typ, rng) in schema.items():
        if field not in values:
            continue
        v = values[field]
        try:
            v = _coerce(typ, v, rng)
        except (TypeError, ValueError) as e:
            return False, f'{field}: invalid {typ} ({e})'
        patch[field] = v
    if not patch:
        return False, 'no valid fields'

    ov = get_overrides()
    merged = dict(ov.get(section) or {})
    merged.update(patch)
    ov[section] = merged
    try:
        ensure_table()
        from . import db
        conn = db.get_conn()
        try:
            conn.cursor().execute(
                'INSERT INTO app_settings (key, value) VALUES (?, ?) '
                'ON CONFLICT(key) DO UPDATE SET value = excluded.value, '
                'updated_at = CURRENT_TIMESTAMP', (_KEY, json.dumps(ov)))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        return False, f'db write failed: {e}'

    # 热生效：原地更新 configs 字典（消费方每次重读）
    target = getattr(configs, _SECTION_TARGET[section], None)
    if isinstance(target, dict):
        target.update(patch)
    logger.info(f"ops_settings saved: {section} -> {_mask(section, patch)}")
    return True, ''
