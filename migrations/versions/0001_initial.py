"""初始基线迁移

复用 smart_init.smart_init() 的幂等建表逻辑（users/oauth/debug-console/social/pricing/
upstreams 等 31 张表），确保与现有部署完全一致。smart_init 本身是幂等的
（IF NOT EXISTS + 字段补全），故本基线迁移可安全重入。

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-23
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """建立全部业务表（与 smart_init 保持一致）。"""
    from APIProxy import smart_init
    smart_init.smart_init()


def downgrade() -> None:
    """初始基线不支持回滚（表结构由 smart_init 管理，回滚会破坏生产数据）。"""
    pass
