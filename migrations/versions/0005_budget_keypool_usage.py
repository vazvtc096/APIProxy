"""月度预算 + 上游密钥池 + 上游真实 token 校准

- users 新列：monthly_budget（月度消费上限，0=不限）/ budget_spent（本月已消费）/
  budget_month（累计所属月份 YYYY-MM）
- upstreams 新列：api_keys（备用密钥池，逗号分隔，空 = 单 key）
- usage_logs 新列：real_prompt_tokens / real_completion_tokens（上游真实 usage，
  NULL = 未捕获），与字符计费口径并存供校准报表

幂等可重入，且方言无关（SQLite / PostgreSQL 通用）。

Revision ID: 0005_budget_keypool_usage
Revises: 0004_token_ratelimit
Create Date: 2026-10-01
"""

from alembic import op
from sqlalchemy import inspect

revision = "0005_budget_keypool_usage"
down_revision = "0004_token_ratelimit"
branch_labels = None
depends_on = None


def _add_column(table: str, column: str, ddl: str) -> None:
    insp = inspect(op.get_bind())
    if table not in insp.get_table_names():
        return
    if column not in {c["name"] for c in insp.get_columns(table)}:
        op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def upgrade() -> None:
    _add_column("users", "monthly_budget", "REAL DEFAULT 0")
    _add_column("users", "budget_spent", "REAL DEFAULT 0")
    _add_column("users", "budget_month", "TEXT DEFAULT ''")
    _add_column("upstreams", "api_keys", "TEXT DEFAULT ''")
    _add_column("usage_logs", "real_prompt_tokens", "INTEGER")
    _add_column("usage_logs", "real_completion_tokens", "INTEGER")


def downgrade() -> None:
    # 保留列不删（列回删丢数据；0/NULL 即视为关闭语义）
    pass
