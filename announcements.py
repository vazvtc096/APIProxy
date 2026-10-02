"""公告 / 通知模块

设计：公告完全复用聊天体系投递——每条公告为一条 type='announcement' 的
chat_messages，发送方为内置 admin。由于所有用户都默认与 admin 互为好友
（受保护、不可删除），因此用户在「消息」里就能直接看到公告并计入未读红点。

announcements 表保存公告本体（标题/正文/级别/受众/投递人数），
chat_messages 保存每个用户的投递副本（通过 announcement_id 关联）。
"""

from __future__ import annotations

import logging
import uuid
from typing import Callable, List, Optional

__all__ = [
    'init_announcements',
    'ensure_admin_friendship',
    'broadcast_announcement',
    'list_announcements',
    'get_announcement',
    'delete_announcement',
    'my_announcements',
    'ANNOUNCEMENT_LEVELS',
]

ANNOUNCEMENT_LEVELS = ('info', 'warning', 'critical')

_db_query: Optional[Callable] = None
_gen_id: Optional[Callable] = None


def init_announcements(db_query: Callable, message_id_gen: Optional[Callable] = None) -> None:
    """注入依赖，避免与 __main__ 循环导入"""
    global _db_query, _gen_id
    _db_query = db_query
    _gen_id = message_id_gen or (lambda: 'msg_' + uuid.uuid4().hex[:16])
    logging.info('[announcements] 公告模块已初始化')


def _db() -> Callable:
    if _db_query is None:
        raise RuntimeError('公告模块未初始化（init_announcements 未调用）')
    return _db_query


def _new_msg_id() -> str:
    return _gen_id() if _gen_id else 'msg_' + uuid.uuid4().hex[:16]


async def _get_admin() -> Optional[dict]:
    db = _db()
    rows = await db("SELECT uid, user_name FROM users WHERE user_name = 'admin' LIMIT 1")
    if not rows:
        rows = await db("SELECT uid, user_name FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1")
    return rows[0] if rows else None


# ---------------------------------------------------------------- 默认好友
async def ensure_admin_friendship(user_uid: str, user_name: str) -> bool:
    """确保指定用户与内置 admin 互为好友（受保护，不可删除）。注册时调用。"""
    if not user_uid:
        return False
    db = _db()
    admin = await _get_admin()
    if not admin or admin['uid'] == user_uid:
        return False
    admin_uid, admin_name = admin['uid'], admin['user_name']

    for a_uid, b_uid, b_name in ((user_uid, admin_uid, admin_name),
                                 (admin_uid, user_uid, user_name)):
        rows = await db(
            "SELECT id FROM friends WHERE user_uid = ? AND friend_uid = ?",
            (a_uid, b_uid)
        )
        if rows:
            await db(
                "UPDATE friends SET status = 'accepted', is_protected = 1, friend_name = ? WHERE id = ?",
                (b_name, rows[0]['id'])
            )
        else:
            await db(
                """INSERT INTO friends (user_uid, friend_uid, friend_name, status, is_protected, accepted_at)
                   VALUES (?, ?, ?, 'accepted', 1, CURRENT_TIMESTAMP)""",
                (a_uid, b_uid, b_name)
            )
    return True


# ---------------------------------------------------------------- 发布公告
async def broadcast_announcement(title: str, content: str, level: str = 'info',
                                 sender_uid: str = '', sender_name: str = '',
                                 target: str = 'all', target_uids: Optional[List[str]] = None,
                                 pinned: bool = False) -> int:
    """发布公告并投递给目标用户，返回投递人数。

    target:
      - 'all'    全体用户
      - 'users'  仅普通用户（非管理员）
      - 'admins' 仅管理员
      - 'custom' 由 target_uids 指定
    """
    db = _db()
    title = (title or '').strip()[:200]
    content = (content or '').strip()[:5000]
    if not title and not content:
        raise ValueError('标题与内容不能同时为空')
    if not content:
        content = title
    if level not in ANNOUNCEMENT_LEVELS:
        level = 'info'

    admin = await _get_admin()
    if not sender_uid:
        # 发件人兜底：优先 admin，其次系统虚拟用户 0x0「系统」（恒定 UID，可进聊天）
        try:
            from .system_users import FALLBACK_UID, get_system_user
            sys_name = get_system_user(FALLBACK_UID)[1]
        except Exception:
            FALLBACK_UID, sys_name = '000000000000', '系统'
        sender_uid = admin['uid'] if admin else FALLBACK_UID
        sender_name = admin['user_name'] if admin else sys_name

    # 解析收件人
    if target == 'custom':
        uids = [u for u in (target_uids or []) if u]
        if not uids:
            raise ValueError('自定义受众需要至少一个用户')
        placeholders = ','.join('?' * len(uids))
        recipients = await db(
            f"SELECT uid, user_name FROM users WHERE uid IN ({placeholders})", tuple(uids)
        ) or []
    elif target == 'users':
        recipients = await db(
            "SELECT uid, user_name FROM users WHERE COALESCE(is_admin,0) = 0 AND uid IS NOT NULL AND uid != ''"
        ) or []
    elif target == 'admins':
        recipients = await db(
            "SELECT uid, user_name FROM users WHERE is_admin = 1 AND uid IS NOT NULL AND uid != ''"
        ) or []
    else:
        target = 'all'
        recipients = await db(
            "SELECT uid, user_name FROM users WHERE uid IS NOT NULL AND uid != ''"
        ) or []

    # 排除系统虚拟用户（UID 池 0~15）：系统不给自己/其他系统投递公告副本
    try:
        from .system_users import is_system_uid as _is_sys
        recipients = [r for r in recipients if not _is_sys(r['uid'])]
    except Exception:
        pass

    announcement_id = 'ann_' + uuid.uuid4().hex[:12]
    await db(
        """INSERT INTO announcements
           (announcement_id, title, content, level, target, target_detail,
            sender_uid, sender_name, recipients, pinned, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP)""",
        (announcement_id, title, content, level, target,
         ','.join(target_uids or []) if target == 'custom' else '',
         sender_uid, sender_name, 1 if pinned else 0)
    )

    # 投递为聊天消息（正文里带上标题，前端按 type='announcement' 特殊渲染）
    # + 同时写入 notifications 表（通知铃铛的权威数据源，与好友关系解耦）
    body = f'【{title}】\n{content}' if title else content
    delivered = 0
    notif_ok = 0
    from . import configs as _cfg
    _to_chat = bool(_cfg.ANNOUNCEMENT_DELIVER_TO_CHAT)
    for r in recipients:
        uid = r.get('uid')
        if not uid:
            continue
        # 通知铃铛（始终写入，作为公告的权威收件箱）
        try:
            from . import notifications as _ntf
            nid = await _ntf.add_notification(
                uid, title or '系统公告', content, level,
                link='/notifications', announcement_id=announcement_id)
            if nid:
                notif_ok += 1
        except Exception as e:
            logging.error(f'[announcements] 通知写入失败 {uid}: {e}')
        # 兼容旧行为：额外投递到 admin 好友聊天会话
        if _to_chat:
            try:
                await db(
                    """INSERT INTO chat_messages
                       (message_id, from_uid, from_name, to_uid, to_name, content,
                        type, status, is_read, announcement_id, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, 'announcement', 'sent', 0, ?, CURRENT_TIMESTAMP)""",
                    (_new_msg_id(), sender_uid, sender_name, uid, r.get('user_name', ''),
                     body, announcement_id)
                )
                delivered += 1
            except Exception as e:
                logging.error(f'[announcements] 投递给 {uid} 失败: {e}')
    if not _to_chat:
        delivered = notif_ok

    await db("UPDATE announcements SET recipients = ? WHERE announcement_id = ?",
             (delivered, announcement_id))
    logging.info(f'[announcements] 公告 {announcement_id} 已投递 {delivered} 人')
    return delivered


# ---------------------------------------------------------------- 查询
async def list_announcements(page: int = 1, per_page: int = 20) -> dict:
    db = _db()
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 100))
    offset = (page - 1) * per_page
    rows = await db(
        """SELECT a.*,
                  (SELECT COUNT(*) FROM chat_messages m
                   WHERE m.announcement_id = a.announcement_id AND m.is_read = 1) as read_count
           FROM announcements a
           ORDER BY a.pinned DESC, a.id DESC LIMIT ? OFFSET ?""",
        (per_page, offset)
    ) or []
    total_rows = await db("SELECT COUNT(*) as cnt FROM announcements")
    total = total_rows[0]['cnt'] if total_rows else 0
    return {'announcements': rows, 'total': total, 'page': page, 'per_page': per_page}


async def get_announcement(announcement_id: str) -> Optional[dict]:
    db = _db()
    rows = await db("SELECT * FROM announcements WHERE announcement_id = ?", (announcement_id,))
    return rows[0] if rows else None


async def delete_announcement(announcement_id: str, purge_messages: bool = True) -> bool:
    """撤回公告：删除公告记录，可选同时撤回已投递的消息副本"""
    db = _db()
    n = await db("DELETE FROM announcements WHERE announcement_id = ?", (announcement_id,))
    if purge_messages:
        await db("DELETE FROM chat_messages WHERE announcement_id = ?", (announcement_id,))
    return bool(n)


async def my_announcements(user_uid: str, limit: int = 30) -> List[dict]:
    """当前用户收到的公告（含已读状态）"""
    db = _db()
    limit = max(1, min(int(limit), 100))
    return await db(
        """SELECT m.message_id, m.content, m.is_read, m.created_at, m.announcement_id,
                  a.title, a.level, a.sender_name, a.pinned
           FROM chat_messages m
           LEFT JOIN announcements a ON a.announcement_id = m.announcement_id
           WHERE m.to_uid = ? AND m.type = 'announcement'
           ORDER BY m.id DESC LIMIT ?""",
        (user_uid, limit)
    ) or []
