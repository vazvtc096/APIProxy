"""令牌级管控 + 兑换码

- apikeys 策略列：label / expires_at / quota / used / allowed_models / ip_whitelist / is_active
- redeem_codes 表：充值兑换码（批量生成、核销入账）

全部使用 IF NOT EXISTS / IF NOT EXISTS 列，幂等可重入。

Revision ID: 0003_token_policy_redeem
Revises: 0002_routing_groups
Create Date: 2026-10-01
"""

from alembic import op

revision = "0003_token_policy_redeem"
down_revision = "0002_routing_groups"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS label VARCHAR DEFAULT ''")
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP")
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS quota DOUBLE PRECISION")
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS used DOUBLE PRECISION DEFAULT 0")
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS allowed_models VARCHAR DEFAULT ''")
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS ip_whitelist VARCHAR DEFAULT ''")
    op.execute("ALTER TABLE apikeys ADD COLUMN IF NOT EXISTS is_active INTEGER DEFAULT 1")
    op.execute("""
        CREATE TABLE IF NOT EXISTS redeem_codes (
            id SERIAL PRIMARY KEY,
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
