"""上游 usage 深度利用：reasoning / cache 命中落库

- usage_logs 新列：real_reasoning_tokens（completion_tokens_details.
  reasoning_tokens，观察推理成本占比）/ real_cache_hit_tokens
  （prompt_cache_hit_tokens 或 prompt_tokens_details.cached_tokens，
  缓存命中输入按折扣计价的数据依据）。NULL = 未捕获。

幂等可重入。

Revision ID: 0006_usage_details
Revises: 0005_budget_keypool_usage
Create Date: 2026-10-01
"""

from alembic import op

revision = "0006_usage_details"
down_revision = "0005_budget_keypool_usage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS real_reasoning_tokens INTEGER")
    op.execute("ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS real_cache_hit_tokens INTEGER")


def downgrade() -> None:
    # 保留列不删（列回删丢数据；NULL 即视为未捕获语义）
    pass
