"""上游 usage 深度利用：reasoning / cache 命中落库

- usage_logs 新列：real_reasoning_tokens（completion_tokens_details.
  reasoning_tokens，观察推理成本占比）/ real_cache_hit_tokens
  （prompt_cache_hit_tokens 或 prompt_tokens_details.cached_tokens，
  缓存命中输入按折扣计价的数据依据）。NULL = 未捕获。

幂等可重入，且方言无关（SQLite / PostgreSQL 通用）。

Revision ID: 0006_usage_details
Revises: 0005_budget_keypool_usage
Create Date: 2026-10-01
"""

from alembic import op
from sqlalchemy import inspect

revision = "0006_usage_details"
down_revision = "0005_budget_keypool_usage"
branch_labels = None
depends_on = None


def _add_column(table: str, column: str, ddl: str) -> None:
    insp = inspect(op.get_bind())
    if table not in insp.get_table_names():
        return
    if column not in {c["name"] for c in insp.get_columns(table)}:
        op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def upgrade() -> None:
    _add_column("usage_logs", "real_reasoning_tokens", "INTEGER")
    _add_column("usage_logs", "real_cache_hit_tokens", "INTEGER")


def downgrade() -> None:
    # 保留列不删（列回删丢数据；NULL 即视为未捕获语义）
    pass
