"""用户组：每个用户属于一个组（默认 'default'），组定义可调模型与价格倍率。

- users.user_group 列存组名（默认 'default'）；user_groups 表存组定义。
- allowed_models 为逗号分隔模型名；空 = 不限制（可调全部）。
  支持 '前缀*' 通配（如 'deepseek-*'）。
- price_multiplier：该组用户的计费倍率（1.0 = 原价）。
- 组行 15s 缓存；管理端改组后调用 invalidate_cache()。
"""
import logging
import time

from . import db

_CACHE = {'rows': None, 'ts': 0.0}
_CACHE_TTL = 15.0
DEFAULT_GROUP = 'default'


def invalidate_cache():
    _CACHE['rows'] = None
    _CACHE['ts'] = 0.0


def _load_groups() -> dict:
    now = time.time()
    if _CACHE['rows'] is not None and now - _CACHE['ts'] < _CACHE_TTL:
        return _CACHE['rows']
    rows = {}
    try:
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT name, allowed_models, price_multiplier, note FROM user_groups")
            for r in cur.fetchall():
                d = dict(r)
                rows[d['name']] = {
                    'allowed_models': [m.strip() for m in (d.get('allowed_models') or '').split(',') if m.strip()],
                    'price_multiplier': float(d.get('price_multiplier') or 1.0),
                    'note': d.get('note') or '',
                }
        finally:
            conn.close()
    except Exception as e:
        logging.error(f"load user_groups failed: {e}")
    _CACHE['rows'] = rows
    _CACHE['ts'] = now
    return rows


def list_groups() -> dict:
    return dict(_load_groups())


def get_group(name: str) -> dict | None:
    return _load_groups().get(name)


def upsert_group(name: str, allowed_models: list | None = None,
                 price_multiplier: float = None, note: str = None) -> bool:
    """创建/更新组。allowed_models=None 表示不改该字段。"""
    if not name or not name.strip():
        raise ValueError('group name required')
    name = name.strip()
    conn = db.get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT allowed_models, price_multiplier, note FROM user_groups WHERE name = ?", (name,))
        row = cur.fetchone()
        cur_allowed = dict(row)['allowed_models'] if row else ''
        cur_mult = float(dict(row)['price_multiplier']) if row else 1.0
        cur_note = (dict(row).get('note') or '') if row else ''
        new_allowed = cur_allowed if allowed_models is None else ','.join(
            m.strip() for m in allowed_models if m and m.strip())
        new_mult = cur_mult if price_multiplier is None else float(price_multiplier)
        new_note = cur_note if note is None else str(note)
        cur.execute(
            """INSERT INTO user_groups (name, allowed_models, price_multiplier, note)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET allowed_models=excluded.allowed_models,
                 price_multiplier=excluded.price_multiplier, note=excluded.note""",
            (name, new_allowed, new_mult, new_note))
        conn.commit()
    finally:
        conn.close()
    invalidate_cache()
    return True


def delete_group(name: str) -> int:
    """删除组；组内用户回退到 default。default 组不可删。"""
    if name == DEFAULT_GROUP:
        raise ValueError('default group cannot be deleted')
    conn = db.get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET user_group = ? WHERE user_group = ?", (DEFAULT_GROUP, name))
        moved = cur.rowcount
        cur.execute("DELETE FROM user_groups WHERE name = ?", (name,))
        n = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    invalidate_cache()
    return n


def get_user_group(owner: str) -> str:
    """用户的组名（无列/无行/空值一律回退 default）"""
    try:
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT user_group FROM users WHERE user_name = ?", (owner,))
            row = cur.fetchone()
            if row:
                return (dict(row).get('user_group') or DEFAULT_GROUP) or DEFAULT_GROUP
        finally:
            conn.close()
    except Exception as e:
        logging.error(f"get_user_group failed: {e}")
    return DEFAULT_GROUP


def set_user_group(owner: str, group: str) -> bool:
    if group != DEFAULT_GROUP and not get_group(group):
        raise ValueError(f"group '{group}' does not exist")
    conn = db.get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET user_group = ? WHERE user_name = ?", (group, owner))
        n = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return n > 0


def _match_any(model: str, patterns: list) -> bool:
    for p in patterns:
        if p.endswith('*'):
            if model.startswith(p[:-1]):
                return True
        elif p == model:
            return True
    return False


def check_model_access(owner: str, model: str) -> tuple:
    """返回 (allowed: bool, reason: str, multiplier: float)。组不存在/未配置 = 不限制。"""
    gname = get_user_group(owner)
    g = get_group(gname)
    mult = g['price_multiplier'] if g else 1.0
    if not g or not g['allowed_models']:
        return True, '', mult
    if _match_any(model, g['allowed_models']):
        return True, '', mult
    return False, f"模型 '{model}' 不在用户组 '{gname}' 允许的范围内", mult


def price_multiplier(owner: str) -> float:
    gname = get_user_group(owner)
    g = get_group(gname)
    return g['price_multiplier'] if g else 1.0
