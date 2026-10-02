"""站内通知模块（铃铛 / 公告收件箱）

设计目标：把「通知 / 公告」从原先寄生在 admin 这个「受保护好友」聊天会话的
hack 中解放出来，成为一等公民。每条通知独立存入 notifications 表，前端通过
右上角铃铛实时读取未读数与列表，与好友关系彻底解耦——既修复了「admin 显示为
好友、但判定/交互脆弱」的不一致，也让公告有了稳定、可标记已读的独立收件箱。

announcements 模块在广播公告时会调用本模块的 add_notification()，将同一份
公告同时写入每个收件人的 notifications 行（是否仍额外投递到 admin 好友聊天
会话，由 configs.ANNOUNCEMENT_DELIVER_TO_CHAT 控制，默认 True 以保持兼容）。
"""

from __future__ import annotations

import logging
import uuid
from typing import Callable, List, Optional

from . import cache_store

# 通知列表 / 未读数缓存 TTL（秒）。通知非高频变更，短缓存即可显著削减
# 铃铛轮询与列表接口对 SQLite 的聚合查询压力；写入 / 已读时精准失效。
_NOTIF_LIST_TTL = 10
_NOTIF_UNREAD_TTL = 10

__all__ = [
    'init_notifications',
    'ensure_notifications_table',
    'add_notification',
    'get_notifications',
    'unread_count',
    'mark_read',
]

NOTIFICATION_LEVELS = ('info', 'warning', 'critical')

_db_query: Optional[Callable] = None


def init_notifications(db_query: Callable) -> None:
    """注入依赖（async_db_query），避免与 __main__ 循环导入。"""
    global _db_query
    _db_query = db_query
    logging.info('[notifications] 通知模块已初始化')


def _db() -> Callable:
    if _db_query is None:
        raise RuntimeError('通知模块未初始化（init_notifications 未调用）')
    return _db_query


async def ensure_notifications_table() -> None:
    """创建 notifications 表与索引（幂等）。"""
    db = _db()
    await db(
        """CREATE TABLE IF NOT EXISTS notifications (
               id              TEXT PRIMARY KEY,
               user_uid        TEXT NOT NULL,
               title           TEXT,
               body            TEXT,
               level           TEXT DEFAULT 'info',
               link            TEXT,
               announcement_id TEXT,
               is_read         INTEGER DEFAULT 0,
               created_at      TEXT DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    await db("CREATE INDEX IF NOT EXISTS idx_notif_uid ON notifications(user_uid)")
    await db("CREATE INDEX IF NOT EXISTS idx_notif_uid_read ON notifications(user_uid, is_read)")
    await db("CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at)")


async def add_notification(user_uid: str, title: str, body: str,
                           level: str = 'info', link: str = '',
                           announcement_id: str = '') -> Optional[str]:
    """给单个用户写入一条通知，返回通知 id；失败返回 None（不阻断主流程）。"""
    if not user_uid:
        return None
    if level not in NOTIFICATION_LEVELS:
        level = 'info'
    title = (title or '').strip()[:300]
    body = (body or '').strip()[:8000]
    link = (link or '').strip()[:2000]
    nid = None
    try:
        nid = 'ntf_' + uuid.uuid4().hex[:14]
        await _db()(
            """INSERT INTO notifications
               (id, user_uid, title, body, level, link, announcement_id, is_read, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)""",
            (nid, user_uid, title, body, level, link, announcement_id or '')
        )
        return nid
    except Exception as e:
        logging.error(f'[notifications] add_notification failed for {user_uid}: {e}')
        return None
    finally:
        # 写入即失效该用户相关缓存（列表 + 未读数），保证下次读取取到新通知
        if nid:
            cache_store.cache_delete_pattern(f"notif:list:{user_uid}:*")
            cache_store.cache_delete_pattern(f"notif:unread:{user_uid}")


async def get_notifications(user_uid: str, limit: int = 30,
                            unread_only: bool = False) -> List[dict]:
    """取某用户的通知列表（按时间倒序）。结果按 uid+limit+unread 维度短缓存。"""
    if not user_uid:
        return []
    cache_key = f"notif:list:{user_uid}:{int(limit)}:{1 if unread_only else 0}"
    cached = cache_store.cache_get_json(cache_key)
    if cached is not None:
        return cached
    db = _db()
    sql = "SELECT * FROM notifications WHERE user_uid = ?"
    if unread_only:
        sql += " AND COALESCE(is_read, 0) = 0"
    sql += " ORDER BY created_at DESC LIMIT ?"
    try:
        rows = await db(sql, (user_uid, int(limit)))
        result = [dict(r) for r in (rows or [])]
    except Exception as e:
        logging.error(f'[notifications] get_notifications failed for {user_uid}: {e}')
        return []
    cache_store.cache_set_json(cache_key, result, _NOTIF_LIST_TTL)
    return result


async def unread_count(user_uid: str) -> int:
    """未读通知数（按 uid 短缓存）。"""
    if not user_uid:
        return 0
    cache_key = f"notif:unread:{user_uid}"
    cached = cache_store.cache_get_json(cache_key)
    if cached is not None:
        return int(cached)
    db = _db()
    try:
        rows = await db(
            "SELECT COUNT(*) as cnt FROM notifications WHERE user_uid = ? AND COALESCE(is_read, 0) = 0",
            (user_uid,)
        )
        cnt = rows[0]['cnt'] if rows else 0
    except Exception as e:
        logging.error(f'[notifications] unread_count failed for {user_uid}: {e}')
        return 0
    cache_store.cache_set_json(cache_key, cnt, _NOTIF_UNREAD_TTL)
    return cnt


async def mark_read(user_uid: str, notif_id: Optional[str] = None) -> int:
    """标记已读。notif_id 为 None / 'all' 时标记该用户全部；否则标记单条。返回影响行数。"""
    if not user_uid:
        return 0
    db = _db()
    try:
        if notif_id and notif_id != 'all':
            rows = await db(
                "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_uid = ?",
                (notif_id, user_uid)
            )
        else:
            rows = await db(
                "UPDATE notifications SET is_read = 1 WHERE user_uid = ?",
                (user_uid,)
            )
        # async_db_query 对写操作返回 cur.rowcount（整数），直接返回即可
        return int(rows or 0)
    except Exception as e:
        logging.error(f'[notifications] mark_read failed for {user_uid}: {e}')
        return 0
    finally:
        # 已读即失效该用户相关缓存，保证铃铛红点 / 列表立即更新
        cache_store.cache_delete_pattern(f"notif:list:{user_uid}:*")
        cache_store.cache_delete_pattern(f"notif:unread:{user_uid}")
