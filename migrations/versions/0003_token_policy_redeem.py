"""令牌级管控 + 兑换码

- apikeys 策略列：label / expires_at / quota / used / allowed_models / ip_whitelist / is_active
- redeem_codes 表：充值兑换码（批量生成、核销入账）

幂等可重入，且方言无关（SQLite / PostgreSQL 通用）。
（原实现使用 PG 专有的 `ADD COLUMN IF NOT EXISTS` / `SERIAL`，SQLite 下报语法错误。）

Revision ID: 0003_token_policy_redeem
Revises: 0002_routing_groups
Create Date: 2026-10-01
"""

from alembic import op
from sqlalchemy import inspect

revision = "0003_token_policy_redeem"
down_revision = "0002_routing_groups"
branch_labels = None
depends_on = None


def _pk_type() -> str:
    return ("SERIAL PRIMARY KEY"
            if op.get_bind().dialect.name == "postgresql"
            else "INTEGER PRIMARY KEY AUTOINCREMENT")


def _add_column(table: str, column: str, ddl: str) -> None:
    insp = inspect(op.get_bind())
    if table not in insp.get_table_names():
        return
    if column not in {c["name"] for c in insp.get_columns(table)}:
        op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def upgrade() -> None:
    for col, ddl in (
        ("label", "VARCHAR DEFAULT ''"),
        ("expires_at", "TIMESTAMP"),
        ("quota", "DOUBLE PRECISION"),
        ("used", "DOUBLE PRECISION DEFAULT 0"),
        ("allowed_models", "VARCHAR DEFAULT ''"),
        ("ip_whitelist", "VARCHAR DEFAULT ''"),
        ("is_active", "INTEGER DEFAULT 1"),
    ):
        _add_column("apikeys", col, ddl)
    op.execute(f"""
        CREATE TABLE IF NOT EXISTS redeem_codes (
            id {_pk_type()},
            code VARCHAR UNIQUE NOT NULL,
            amount DOUBLE PRECISION NOT NULL,
            created_by VARCHAR,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            redeemed_by VARCHAR,
            redeemed_at TIMESTAMP,
            note VARCHAR DEFAULT ''
        )
    """)
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_redeem_code ON redeem_codes(code)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_redeem_redeemed_by ON redeem_codes(redeemed_by)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS redeem_codes")
    # apikeys 策略列保留不删（列回删会丢令牌策略数据）
