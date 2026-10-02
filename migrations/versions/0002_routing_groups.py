"""路由层特性：用户组 + 模型映射

- user_groups 表：每用户属于一个组（默认 default），组定义可调模型与价格倍率
- users.user_group 列：用户所属组（默认 'default'）
- model_mappings 表：请求模型 A → 上游 B（空=任意/多个=候选集）的模型 C

全部使用 IF NOT EXISTS / IF NOT EXISTS 列，幂等可重入。

Revision ID: 0002_routing_groups
Revises: 0001_initial
Create Date: 2026-10-01
"""

from alembic import op

revision = "0002_routing_groups"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


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
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS user_group VARCHAR DEFAULT 'default'")
    op.execute("""
        CREATE TABLE IF NOT EXISTS model_mappings (
            id SERIAL PRIMARY KEY,
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
