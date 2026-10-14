"""路由层特性：用户组 + 模型映射

- user_groups 表：每用户属于一个组（默认 default），组定义可调模型与价格倍率
- users.user_group 列：用户所属组（默认 'default'）
- model_mappings 表：请求模型 A → 上游 B（空=任意/多个=候选集）的模型 C

幂等可重入，且方言无关（SQLite / PostgreSQL 通用）。
历史问题：原实现用 `ADD COLUMN IF NOT EXISTS` 与 `SERIAL PRIMARY KEY`（均为
PostgreSQL 专有语法），导致 SQLite 环境执行到本迁移即报语法错误，整条迁移链
（0002 及之后）从未在 SQLite 上落地。现改为「先 inspect 再改」+ 按方言选主键类型。

Revision ID: 0002_routing_groups
Revises: 0001_initial
Create Date: 2026-10-01
"""

from alembic import op
from sqlalchemy import inspect

revision = "0002_routing_groups"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _dialect() -> str:
    return op.get_bind().dialect.name


def _pk_type() -> str:
    """自增主键类型：PG 用 SERIAL，SQLite 用 INTEGER PRIMARY KEY AUTOINCREMENT。"""
    return "SERIAL PRIMARY KEY" if _dialect() == "postgresql" else "INTEGER PRIMARY KEY AUTOINCREMENT"


def _add_column(table: str, column: str, ddl: str) -> None:
    """列不存在时才加列（跨方言幂等）。"""
    insp = inspect(op.get_bind())
    if table not in insp.get_table_names():
        return
    if column not in {c["name"] for c in insp.get_columns(table)}:
        op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS user_groups (
            name VARCHAR PRIMARY KEY,
            allowed_models VARCHAR DEFAULT '',
            price_multiplier DOUBLE PRECISION DEFAULT 1.0,
            note VARCHAR DEFAULT ''
        )
    """)
    op.execute(
        "INSERT INTO user_groups (name, allowed_models, price_multiplier, note) "
        "SELECT 'default', '', 1.0, '默认组：可调用全部模型' "
        "WHERE NOT EXISTS (SELECT 1 FROM user_groups WHERE name = 'default')"
    )
    _add_column("users", "user_group", "VARCHAR DEFAULT 'default'")
    op.execute(f"""
        CREATE TABLE IF NOT EXISTS model_mappings (
            id {_pk_type()},
            pattern VARCHAR NOT NULL,
            upstreams VARCHAR DEFAULT '',
            target_model VARCHAR NOT NULL,
            enabled INTEGER DEFAULT 1
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS model_mappings")
    op.execute("DROP TABLE IF EXISTS user_groups")
    # users.user_group 保留不删（列回删会丢用户分组数据）
