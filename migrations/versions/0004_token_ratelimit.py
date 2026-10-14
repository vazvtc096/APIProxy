"""令牌级 RPM/TPM 限速

- apikeys 新列：rpm_limit（每分钟请求数上限）/ tpm_limit（每分钟字符量上限），0 = 不限
- 计数走 cache_store（Redis/集群共享），不落库

幂等可重入，且方言无关（SQLite / PostgreSQL 通用）。

Revision ID: 0004_token_ratelimit
Revises: 0003_token_policy_redeem
Create Date: 2026-10-01
"""

from alembic import op
from sqlalchemy import inspect

revision = "0004_token_ratelimit"
down_revision = "0003_token_policy_redeem"
branch_labels = None
depends_on = None


def _add_column(table: str, column: str, ddl: str) -> None:
    insp = inspect(op.get_bind())
    if table not in insp.get_table_names():
        return
    if column not in {c["name"] for c in insp.get_columns(table)}:
        op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def upgrade() -> None:
    _add_column("apikeys", "rpm_limit", "INTEGER DEFAULT 0")
    _add_column("apikeys", "tpm_limit", "INTEGER DEFAULT 0")


def downgrade() -> None:
    # 限速列保留不删（列回删会丢策略数据；0 即视为不限）
    pass
