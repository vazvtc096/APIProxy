"""系统虚拟用户（UID 池 0~15）

保留 UID 段：000000000000 ~ 00000000000f（12 位十六进制，与 generate_uid()
的 uuid4().hex[:12] 格式一致）。真实用户注册命中该段概率为零（2^-48 级），
但注册路径仍显式守卫，保证 UID 恒定可依赖。

已落库的系统用户（恒定 UID，禁止登录，不出现在搜索/用户管理中）：
  000000000000 (0x0)  system     「系统」      通用兜底发件人（公告/控制台/调度器系统通知）
  000000000001 (0x1)  scheduler   「定时任务」  计划任务产生的通知
  000000000002 (0x2)  hooks       「钩子系统」  钩子引擎动作（notify_admin 等）的发件人
  000000000003~f       —          保留段，不建行，仅供未来扩展

聊天链路的接入方式：
  - /api/chat/conversations 与 /api/friends 会把「有消息往来的系统用户」
    虚拟注入会话列表（is_system=True），无需好友关系行；
  - /api/chat/messages/<uid> 与 /api/chat/send 对系统 UID 跳过好友校验；
  - 历史遗留 from_uid='system' 的消息在 ensure 时一次性迁移到 0x0。
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Dict, Optional, Tuple

__all__ = [
    'SYSTEM_UID_PATTERN',
    'SYSTEM_USERS',
    'FALLBACK_UID',
    'UID_SYSTEM', 'UID_SCHEDULER', 'UID_HOOKS',
    'is_system_uid',
    'get_system_user',
    'system_sender',
    'init_system_users',
    'ensure_system_users',
]

# UID 池：000000000000 ~ 00000000000f（11 个前导 0 + 1 位十六进制）
SYSTEM_UID_PATTERN = re.compile(r'^0{11}[0-9a-f]$')

UID_SYSTEM = '000000000000'    # 0x0 系统（通用兜底）
UID_SCHEDULER = '000000000001'  # 0x1 定时任务
UID_HOOKS = '000000000002'     # 0x2 钩子系统

# uid -> (user_name, display_name, 描述)
SYSTEM_USERS: Dict[str, Tuple[str, str, str]] = {
    UID_SYSTEM: ('system', '系统', '通用系统通知'),
    UID_SCHEDULER: ('scheduler', '定时任务', '计划任务通知'),
    UID_HOOKS: ('hooks', '钩子系统', '钩子引擎通知'),
}

FALLBACK_UID = UID_SYSTEM

# 密码占位：不是任何合法哈希格式，verify_password() 对其恒为 False
_NO_LOGIN_HASH = '!system-virtual-user-no-login'

_db_query: Optional[Callable] = None


def init_system_users(db_query: Callable) -> None:
    """注入依赖（async_db_query），由 core.init_integrations 调用。"""
    global _db_query
    _db_query = db_query


def _db() -> Callable:
    if _db_query is None:
        raise RuntimeError('系统用户模块未初始化（init_system_users 未调用）')
    return _db_query


def is_system_uid(uid: str) -> bool:
    """是否属于系统虚拟用户 UID 池（0~15）。"""
    return bool(uid) and bool(SYSTEM_UID_PATTERN.match(str(uid)))


def get_system_user(uid: str) -> Optional[Tuple[str, str]]:
    """返回 (user_name, display_name)；非系统 UID 返回 None。"""
    entry = SYSTEM_USERS.get(str(uid or ''))
    return (entry[0], entry[1]) if entry else None


def system_sender(uid: str) -> Tuple[str, str]:
    """取系统发件人 (uid, user_name)。未知系统 UID 回退到通用「系统」。"""
    entry = get_system_user(uid)
    if entry:
        return (str(uid), entry[1])
    return (FALLBACK_UID, SYSTEM_USERS[FALLBACK_UID][1])


async def ensure_system_users() -> None:
    """幂等落库系统虚拟用户 + 迁移历史遗留的 from_uid='system' 消息。

    各项失败仅告警不抛出——系统用户缺失时聊天链路退化为旧行为。
    """
    db = _db()
    for uid, (user_name, display_name, _desc) in SYSTEM_USERS.items():
        try:
            rows = await db("SELECT uid FROM users WHERE uid = ?", (uid,))
            if rows:
                continue
            # user_name 可能被真实用户占用（UNIQUE 冲突）：追加序号兜底
            name = user_name
            for attempt in range(4):
                try:
                    await db(
                        """INSERT INTO users (user_name, user_password, uid, is_admin, is_banned)
                           VALUES (?, ?, ?, 0, 1)""",
                        (name, _NO_LOGIN_HASH, uid)
                    )
                    logging.info(f'[system-users] 系统虚拟用户已创建: {name} ({uid})「{display_name}」')
                    break
                except Exception as e:
                    msg = str(e)
                    if 'UNIQUE' in msg or 'duplicate key' in msg.lower():
                        name = f'{user_name}~{uid[-1]}{"~" * (attempt + 1) if attempt else ""}'
                        continue
                    raise
        except Exception as e:
            logging.error(f'[system-users] ensure failed for {uid}: {e}')

    # 历史数据迁移：旧代码以字符串 'system' 作为发件人 UID（非真实用户，
    # 无法进入聊天）。统一归并到 0x0「系统」。
    try:
        await db(
            """UPDATE chat_messages SET from_uid = ?, from_name = '系统'
               WHERE from_uid = 'system'""",
            (UID_SYSTEM,)
        )
    except Exception as e:
        logging.warning(f'[system-users] legacy sender migration skipped: {e}')
