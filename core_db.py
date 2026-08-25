"""数据库基础层：连接获取与异步查询。

从 core.py 拆分而来（阶段 2：God module 拆分）。
这是所有数据访问的基础，被限流、会话、RCON、计费等模块共享。
"""
import asyncio


def _get_conn():
    """获取数据库连接（SQLite / PostgreSQL，经 db 抽象层统一）"""
    from . import db
    return db.get_conn()


async def async_db_query(sql, args=None, fetch_one=False):
    """执行 SQL。SELECT 返回 list[dict]；fetch_one=True 时返回单条 dict 或 None。"""
    def _query():
        conn = _get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute(sql, args or ())
            if sql.strip().upper().startswith("SELECT"):
                if fetch_one:
                    row = cur.fetchone()
                    return dict(row) if row else None
                rows = cur.fetchall()
                return [dict(row) for row in rows]
            else:
                conn.commit()
                return cur.rowcount
    return await asyncio.to_thread(_query)
