# -*- coding: utf-8 -*-
"""调用模型（Playground）持久化会话。

面向普通登录用户的对话式模型调试台：
  - 多对话（playground_conversations），归属 user_name；
  - 每对话消息历史（playground_messages），即"持久上下文"；
  - 发送请求时由 routes/playground.py 组装上下文打包为 chat messages，
    响应流结束后解包回填 assistant 消息。

表在模块 import 时幂等自建（对齐 core_session / tokenpolicy 惯例），新部署免迁移。

导出的同步函数均为纯 DB 操作；路由层用 async_db_query / asyncio.to_thread 调用。
"""
import logging
from datetime import datetime

from .core_db import _get_conn
from . import configs

logger = logging.getLogger(__name__)

# 长度治理改为配置驱动（config.yaml -> playground: 段 -> configs.PLAYGROUND）：
#   context_limit: 随请求携带的历史消息条数上限，0 = 不限制
#   msg_max_len:   单条消息落库最大字符数，0 = 不限制
# 默认均不截断，对齐 /v1 行为：超长由上游模型报错并原样透传状态码。


def _init_tables():
    def _init():
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS playground_conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_name TEXT NOT NULL,
                    title TEXT DEFAULT '',
                    model TEXT DEFAULT '',
                    system_prompt TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pg_conv_user ON playground_conversations(user_name)")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS playground_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    model TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pg_msg_conv ON playground_messages(conversation_id)")
            conn.commit()
    try:
        _init()
    except Exception as e:
        logger.error(f"playground tables init failed: {e}")


_init_tables()


# ============================================================================
# 对话 CRUD（同步；调用方负责归属校验参数）
# ============================================================================
def list_conversations(user_name: str) -> list:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, title, model, system_prompt, created_at, updated_at "
            "FROM playground_conversations WHERE user_name = ? ORDER BY updated_at DESC, id DESC",
            (user_name,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_conversation(conv_id: int, user_name: str):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM playground_conversations WHERE id = ? AND user_name = ?",
            (conv_id, user_name))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_conversation(user_name: str, title: str = "", model: str = "", system_prompt: str = "") -> int:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO playground_conversations (user_name, title, model, system_prompt) VALUES (?,?,?,?)",
            (user_name, (title or "")[:80], (model or "")[:200], (system_prompt or "")))
        conn.commit()
        # PG 的 lastrowid 不可靠（OID 通常为 0），用 MAX(id) 兜底取回（低频单人操作无并发问题）
        cur.execute("SELECT MAX(id) AS id FROM playground_conversations WHERE user_name = ?", (user_name,))
        row = cur.fetchone()
        return int(row["id"]) if row else 0
    finally:
        conn.close()


def update_conversation(conv_id: int, user_name: str, title=None, model=None, system_prompt=None) -> bool:
    """部分更新（None=不改）；updated_at 一并刷新。"""
    sets, args = [], []
    if title is not None:
        sets.append("title = ?"); args.append(str(title)[:80])
    if model is not None:
        sets.append("model = ?"); args.append(str(model)[:200])
    if system_prompt is not None:
        sets.append("system_prompt = ?"); args.append(str(system_prompt))
    if not sets:
        return True
    sets.append("updated_at = ?"); args.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    args += [conv_id, user_name]
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE playground_conversations SET {', '.join(sets)} WHERE id = ? AND user_name = ?", args)
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def delete_conversation(conv_id: int, user_name: str) -> bool:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM playground_messages WHERE conversation_id = ?", (conv_id,))
        cur.execute("DELETE FROM playground_conversations WHERE id = ? AND user_name = ?", (conv_id, user_name))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_messages(conv_id: int, user_name: str) -> bool:
    """清空上下文：删掉该对话全部消息（对话本身保留，含模型/系统提示词设置）。"""
    conv = get_conversation(conv_id, user_name)
    if not conv:
        return False
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM playground_messages WHERE conversation_id = ?", (conv_id,))
        cur.execute("UPDATE playground_conversations SET updated_at = ? WHERE id = ?",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), conv_id))
        conn.commit()
        return True
    finally:
        conn.close()


# ============================================================================
# 消息
# ============================================================================
def list_messages(conv_id: int, limit: int = 500, newest_first: bool = False) -> list:
    """limit <= 0 表示不限制条数；newest_first=True 时取最近 limit 条并按时间正序返回。"""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        if limit and int(limit) > 0:
            order = "ORDER BY id DESC" if newest_first else "ORDER BY id ASC"
            cur.execute(
                "SELECT id, role, content, model, created_at FROM playground_messages "
                f"WHERE conversation_id = ? {order} LIMIT ?",
                (conv_id, int(limit)))
        else:
            cur.execute(
                "SELECT id, role, content, model, created_at FROM playground_messages "
                "WHERE conversation_id = ? ORDER BY id ASC",
                (conv_id,))
        rows = cur.fetchall()
    finally:
        conn.close()
    msgs = [dict(r) for r in rows]
    if newest_first:
        msgs.reverse()
    return msgs


def build_context_messages(conv_id: int, system_prompt: str = "") -> list:
    """组包：系统提示词（可选）+ 最近 context_limit 条历史（0 = 全量，配置驱动）。"""
    msgs = []
    sp = (system_prompt or "").strip()
    if sp:
        msgs.append({"role": "system", "content": sp})
    limit = int((getattr(configs, "PLAYGROUND", None) or {}).get("context_limit") or 0)
    if limit > 0:
        history = list_messages(conv_id, limit=limit, newest_first=True)
    else:
        history = list_messages(conv_id, limit=0)
    for m in history:
        role = m.get("role")
        if role in ("user", "assistant") and m.get("content"):
            msgs.append({"role": role, "content": m["content"]})
    return msgs


def add_message(conv_id: int, role: str, content: str, model: str = "") -> int:
    max_len = int((getattr(configs, "PLAYGROUND", None) or {}).get("msg_max_len") or 0)
    if max_len > 0:
        content = (content or "")[:max_len]
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO playground_messages (conversation_id, role, content, model) VALUES (?,?,?,?)",
            (conv_id, role, content, (model or "")[:200]))
        cur.execute(
            "UPDATE playground_conversations SET updated_at = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), conv_id))
        conn.commit()
        cur.execute("SELECT MAX(id) AS id FROM playground_messages WHERE conversation_id = ?", (conv_id,))
        row = cur.fetchone()
        return int(row["id"]) if row else 0
    finally:
        conn.close()


def count_messages(conv_id: int) -> int:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM playground_messages WHERE conversation_id = ?", (conv_id,))
        row = cur.fetchone()
        return int(row["c"]) if row else 0
    finally:
        conn.close()
