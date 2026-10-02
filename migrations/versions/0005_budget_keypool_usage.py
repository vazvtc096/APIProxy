"""月度预算 + 上游密钥池 + 上游真实 token 校准

- users 新列：monthly_budget（月度消费上限，0=不限）/ budget_spent（本月已消费）/
  budget_month（累计所属月份 YYYY-MM）
- upstreams 新列：api_keys（备用密钥池，逗号分隔，空 = 单 key）
- usage_logs 新列：real_prompt_tokens / real_completion_tokens（上游真实 usage，
  NULL = 未捕获），与字符计费口径并存供校准报表

幂等可重入。

Revision ID: 0005_budget_keypool_usage
Revises: 0004_token_ratelimit
Create Date: 2026-10-01
"""

from alembic import op

revision = "0005_budget_keypool_usage"
down_revision = "0004_token_ratelimit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS monthly_budget REAL DEFAULT 0")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS budget_spent REAL DEFAULT 0")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS budget_month TEXT DEFAULT ''")
    op.execute("ALTER TABLE upstreams ADD COLUMN IF NOT EXISTS api_keys TEXT DEFAULT ''")
    op.execute("ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS real_prompt_tokens INTEGER")
    op.execute("ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS real_completion_tokens INTEGER")


def downgrade() -> None:
    # 保留列不删（列回删丢数据；0/NULL 即视为关闭语义）
    pass
