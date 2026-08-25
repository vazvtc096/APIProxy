"""数据库抽象层：统一 SQLite / PostgreSQL 两种后端。

设计目标：让既有代码（基于 sqlite3 的 `?` 占位符、`dict(row)`、`with conn:`
事务语义）在 PostgreSQL 上无需改动即可运行。

- SQLite（默认）：返回原生 sqlite3 连接（行为完全不变）。
- PostgreSQL：返回 psycopg2 连接 + 游标包装，透明完成：
    1. `?` 占位符 → `%s`（项目 SQL 中 `?` 均为占位符，无字符串字面量歧义）；
    2. 游标返回 dict（RealDictCursor），使 `dict(row)` 照常工作；
    3. `with conn:` 保持 commit/rollback 语义。

配置（configs.py / 环境变量）：
    DB_TYPE      = sqlite | postgres
    DB_PATH      = SQLite 文件路径
    DATABASE_URL = postgresql://user:pass@host:5432/dbname（postgres 时使用）
"""

import os
import re
import threading
from contextlib import contextmanager

from .configs import DB_PATH, DB_TYPE, DATABASE_URL

_POSTGRES = DB_TYPE in ("postgres", "postgresql")

# SQLite 在多线程（asyncio.to_thread 线程池）下需要 check_same_thread=False，
# 并用 busy_timeout 让写冲突时自动等待而非立即抛 database is locked。
# 同时用进程内全局写锁串行化写事务，避免多连接并发写同一文件互相阻塞/损坏。
_SQLITE_WRITE_LOCK = threading.Lock()
_SQLITE_BUSY_TIMEOUT_MS = 30000

# INSERT OR REPLACE 的冲突目标（UNIQUE 或 PRIMARY KEY 列），用于转换为
# PostgreSQL 的 ON CONFLICT (key) DO UPDATE。键为表名，值为冲突目标列。
_INSERT_OR_REPLACE_KEY = {
    "ip_whitelist": "ip",
    "ip_blacklist": "ip",
    "model_prices": "model",
    "upstreams": "name",
    "system_config": "key",
}


def _convert_sql(sql: str) -> str:
    """把 SQLite 方言 SQL 转换为 PostgreSQL 方言（仅在 postgres 后端时调用）。

    处理：
      1. `?` 占位符 → `%s`（项目 SQL 中 `?` 均为参数占位符，无字面量歧义）；
      2. `INSERT OR IGNORE INTO` → `INSERT INTO ... ON CONFLICT DO NOTHING`；
      3. `INSERT OR REPLACE INTO` → `INSERT INTO ... ON CONFLICT (key) DO UPDATE SET ...`；
      4. `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`（建表）。
    """
    if not _POSTGRES:
        return sql

    # 1. 占位符
    sql = sql.replace("?", "%s")

    # 1.5 datetime('now') → CURRENT_TIMESTAMP（SQLite 特有日期函数）
    sql = re.sub(r"datetime\('now'\)", "CURRENT_TIMESTAMP", sql, flags=re.IGNORECASE)

    # datetime('now', '<modifier>') → CURRENT_TIMESTAMP ± INTERVAL（静态修饰符）
    def _dt_modifier(m):
        modifier = m.group(1).strip()
        sign = "+"
        rest = modifier
        if rest.startswith("-"):
            sign = "-"
            rest = rest[1:]
        elif rest.startswith("+"):
            rest = rest[1:]
        return f"CURRENT_TIMESTAMP {sign} INTERVAL '{rest.strip()}'"

    sql = re.sub(
        r"datetime\('now',\s*'([^']+)'\)", _dt_modifier, sql, flags=re.IGNORECASE,
    )

    # datetime('now', ?) → CURRENT_TIMESTAMP + (?::interval)（动态修饰符，? 已转 %s）
    sql = re.sub(
        r"datetime\('now',\s*(%s)\)",
        r"CURRENT_TIMESTAMP + (\1::interval)", sql, flags=re.IGNORECASE,
    )

    # 2. INSERT OR IGNORE → ON CONFLICT DO NOTHING
    if re.search(r"INSERT\s+OR\s+IGNORE\s+INTO", sql, re.IGNORECASE):
        sql = re.sub(
            r"INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", sql,
            count=1, flags=re.IGNORECASE,
        )
        sql = _append_suffix(sql, "ON CONFLICT DO NOTHING")

    # 3. INSERT OR REPLACE → ON CONFLICT (key) DO UPDATE SET ...
    m = re.match(
        r"\s*INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*\(([^)]+)\)",
        sql, re.IGNORECASE,
    )
    if m:
        table = m.group(1).lower()
        key = _INSERT_OR_REPLACE_KEY.get(table)
        if key:
            cols = [c.strip() for c in m.group(2).split(",") if c.strip()]
            set_cols = [c for c in cols if c != key]
            if set_cols:
                set_clause = ", ".join(f"{c}=excluded.{c}" for c in set_cols)
                sql = re.sub(
                    r"INSERT\s+OR\s+REPLACE\s+INTO", "INSERT INTO", sql,
                    count=1, flags=re.IGNORECASE,
                )
                sql = _append_suffix(sql, f"ON CONFLICT ({key}) DO UPDATE SET {set_clause}")

    # 4. AUTOINCREMENT → SERIAL
    sql = re.sub(
        r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
        "SERIAL PRIMARY KEY", sql, flags=re.IGNORECASE,
    )

    # 5. sqlite_master 表存在检查 → information_schema.tables
    sql = re.sub(
        r"SELECT\s+name\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s*=",
        "SELECT table_name AS name FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_name =",
        sql, flags=re.IGNORECASE,
    )

    # 6. PRAGMA table_info(X) → information_schema.columns（返回兼容 6 列结构，
    #    顺序 cid/name/type/notnull/dflt_value/pk，保证既有 col[1] 取值不变）
    def _pragma_to_pg(m):
        table = m.group(1)
        return (
            "SELECT ordinal_position - 1 AS cid, column_name AS name, data_type AS type, "
            "CASE WHEN is_nullable = 'NO' THEN 1 ELSE 0 END AS notnull, "
            "column_default AS dflt_value, 0 AS pk "
            "FROM information_schema.columns "
            f"WHERE table_schema = 'public' AND table_name = '{table}' "
            "ORDER BY ordinal_position"
        )

    sql = re.sub(
        r"PRAGMA\s+table_info\(\s*(\w+)\s*\)",
        _pragma_to_pg, sql, flags=re.IGNORECASE,
    )

    return sql


def _append_suffix(sql: str, suffix: str) -> str:
    """在 SQL 语句末尾追加子句（去掉尾部空白与分号后再加）。"""
    stripped = sql.rstrip()
    had_semicolon = stripped.endswith(";")
    stripped = stripped.rstrip(";").rstrip()
    return stripped + " " + suffix + (";" if had_semicolon else "")


class _Row(dict):
    """dict 子类，额外支持整数索引访问（row[0]），兼容 sqlite3.Row 的两种取值方式。

    sqlite3.Row 同时支持 row[0]（按列序）与 row['col']（按列名），而 psycopg2 的
    RealDictCursor 只返回 dict（仅支持列名）。为让既有代码（含 row[0] 索引访问）
    零改动迁移，用本类包装：整数索引按列顺序映射到列名取值。
    """

    __slots__ = ("_keys",)

    def __init__(self, d, keys):
        super().__init__(d)
        self._keys = keys

    def __getitem__(self, key):
        if isinstance(key, int):
            return super().__getitem__(self._keys[key])
        return super().__getitem__(key)


class _PgCursor:
    """psycopg2 游标包装：透明转换占位符，返回兼容 sqlite3.Row 的行对象。"""

    def __init__(self, cursor):
        self._cursor = cursor
        self._keys = []

    def _wrap(self, row):
        if row is None:
            return None
        if self._keys:
            return _Row(row, self._keys)
        return row

    def execute(self, sql, args=None):
        result = self._cursor.execute(_convert_sql(sql), args)
        self._keys = [d[0] for d in (self._cursor.description or [])]
        return result

    def executemany(self, sql, argslist):
        result = self._cursor.executemany(_convert_sql(sql), argslist)
        self._keys = [d[0] for d in (self._cursor.description or [])]
        return result

    def fetchone(self):
        return self._wrap(self._cursor.fetchone())

    def fetchall(self):
        return [self._wrap(r) for r in self._cursor.fetchall()]

    def fetchmany(self, size=None):
        return [self._wrap(r) for r in self._cursor.fetchmany(size)]

    def close(self):
        return self._cursor.close()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def description(self):
        return self._cursor.description

    def __iter__(self):
        for r in self._cursor:
            yield self._wrap(r)


class _PgConnection:
    """psycopg2 连接包装：模拟 sqlite3 的连接接口与事务语义。

    若构造时传入 pool，则退出 with 块时把连接归还池中（而非关闭），实现连接复用。
    """

    def __init__(self, conn, pool=None):
        self._conn = conn
        self._pool = pool

    def cursor(self):
        import psycopg2.extras
        return _PgCursor(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))

    def execute(self, sql, args=None):
        """连接级快捷执行（等价 sqlite3.Connection.execute，返回游标）。"""
        cur = self.cursor()
        cur.execute(sql, args)
        return cur

    def executemany(self, sql, argslist):
        cur = self.cursor()
        cur.executemany(sql, argslist)
        return cur

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def set_autocommit(self, value: bool):
        """切换 autocommit 模式（仅 PostgreSQL 有意义；SQLite 连接忽略）。

        DDL 初始化（smart_init）等场景需要单语句失败不污染整事务，对齐
        sqlite3 的宽松行为（psycopg2 默认任一错误都会中止事务，导致后续
        except: pass 后的语句全部 InFailedSqlTransaction）。
        """
        ac = getattr(self._conn, "autocommit", None)
        if ac is not None:
            self._conn.autocommit = value

    def close(self):
        if self._pool is not None:
            # 归还到连接池而非真正关闭
            try:
                self._pool.putconn(self._conn)
            except Exception:
                try:
                    self._conn.close()
                except Exception:
                    pass
            return
        return self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            try:
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        else:
            self._conn.rollback()
        return False


# PostgreSQL 连接池（延迟初始化）：避免每次请求都新建连接（原实现开销大）。
_PG_POOL = None
_PG_POOL_LOCK = threading.Lock()


def _get_pg_pool():
    """懒加载 PostgreSQL 连接池（线程安全单例）。"""
    global _PG_POOL
    if _PG_POOL is not None:
        return _PG_POOL
    with _PG_POOL_LOCK:
        if _PG_POOL is not None:
            return _PG_POOL
        import psycopg2
        import psycopg2.pool
        # 池上限 50：启动自检并发突发下每请求经 web_filter/WAF/device-ban/路由
        # 多个中间件各取 1 连接，瞬时并发可超 20；PG 默认 max_connections=100 足够
        _PG_POOL = psycopg2.pool.SimpleConnectionPool(1, 50, DATABASE_URL)
        return _PG_POOL


def get_conn():
    """返回数据库连接（sqlite3 或 psycopg2 包装）。

    调用方无需关心后端，接口与 sqlite3 一致：
        conn = get_conn()
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT ... WHERE x = ?", (val,))
            row = cur.fetchone()
            d = dict(row)  # 两种后端都支持

    并发语义（按 DB_TYPE 自动选择，调用方无需判断）：
    - SQLite：check_same_thread=False + busy_timeout，配合进程内写锁串行化写事务。
    - PostgreSQL：从连接池取连接，行级锁由 SQL（FOR UPDATE）或事务保证。
    """
    if _POSTGRES:
        if not DATABASE_URL:
            raise RuntimeError(
                "DB_TYPE=postgres 但 DATABASE_URL 未配置，"
                "请设置环境变量 DATABASE_URL=postgresql://user:pass@host:5432/dbname"
            )
        pool = _get_pg_pool()
        conn = pool.getconn()
        return _PgConnection(conn, pool)

    import sqlite3

    conn = sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
        timeout=_SQLITE_BUSY_TIMEOUT_MS / 1000.0,
    )
    conn.row_factory = sqlite3.Row
    # busy_timeout 兜底：即便锁不可用，也阻塞等待而非立即失败
    try:
        conn.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_TIMEOUT_MS}")
    except Exception:
        pass
    return conn


@contextmanager
def transaction():
    """统一的写事务上下文（按后端自动选择并发控制），替代分散的裸 BEGIN。

    用法：
        with db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE ...")

    后端差异对调用方透明：
    - SQLite：进程内全局写锁串行化所有写事务（单写者模型的安全做法），
      避免多线程并发写出现 `database is locked`。
    - PostgreSQL：从连接池取连接，事务由 psycopg2 管理；行级互斥由
      SQL 中的 `FOR UPDATE`（业务按需）保证，连接池避免重复建连开销。
    """
    if _POSTGRES:
        if not DATABASE_URL:
            raise RuntimeError(
                "DB_TYPE=postgres 但 DATABASE_URL 未配置，"
                "请设置环境变量 DATABASE_URL=postgresql://user:pass@host:5432/dbname"
            )
        pool = _get_pg_pool()
        conn = _PgConnection(pool.getconn(), pool)
        try:
            with conn:
                yield conn
        finally:
            conn.close()
    else:
        # SQLite：用 BEGIN IMMEDIATE 在事务开始即获取写锁，保证余额扣减等
        # 强一致场景的串行化；busy_timeout 兜底避免 database is locked。
        # 不依赖 Python 全局锁，避免把所有写无差别串行导致吞吐下降。
        conn = get_conn()
        conn.isolation_level = None  # autocommit，便于手动控制事务边界
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()


def sqlite_write_lock():
    """返回 SQLite 进程内写锁（仅 SQLite 模式有意义；PG 行级锁已足够）。

    用法：
        with db.sqlite_write_lock():
            conn = db.get_conn()
            with conn:
                ... 写操作 ...
    """
    return _SQLITE_WRITE_LOCK


def begin_write(conn):
    """标记「这是一个写事务」：在 SQLite 下执行 BEGIN IMMEDIATE 立即获取写锁，
    防止并发写竞态（如余额扣减的读-改-写丢失更新）；PostgreSQL 下 psycopg2
    自动按需开启事务，此函数为 no-op 以保证兼容。

    调用方通常这样用（显式事务，不依赖 `with conn:`）：
        conn = db.get_conn()
        db.begin_write(conn)
        cur = conn.cursor()
        ...
        conn.commit() / conn.rollback()
    """
    if not _POSTGRES:
        conn.execute("BEGIN IMMEDIATE")
    return conn


def is_postgres() -> bool:
    """当前是否使用 PostgreSQL 后端。"""
    return _POSTGRES
