"""令牌级 RPM/TPM 限速

- apikeys 新列：rpm_limit（每分钟请求数上限）/ tpm_limit（每分钟字符量上限），0 = 不限
- 计数走 cache_store（Redis/集群共享），不落库

幂等可重入。

Revision ID: 0004_token_ratelimit
Revises: 0003_token_policy_redeem
Create Date: 2026-10-01
"""

from alembic import op

revision = "0004_token_ratelimit"
down_revision = "0003_token_policy_redeem"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS rpm_limit INTEGER DEFAULT 0")
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS tpm_limit INTEGER DEFAULT 0")


def downgrade() -> None:
    # 限速列保留不删（列回删会丢策略数据；0 即视为不限）
    pass
