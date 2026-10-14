"""在线支付列修正：bank_order_no -> pay_order_no，并新增 pay_qr_url

背景（真实 schema 漂移事故）：
    payments 多支付改造把 recharge_requests.bank_order_no 改名为 pay_order_no，
    但该改名**只写在 smart_init.py / init_db.py 的「Alembic 失败回退」分支**里。
    当部署使用 PostgreSQL 时 Alembic 迁移成功执行、smart_init 从不执行，
    于是改名与新列从未落到真实库 —— 表现为线上「在线支付」在下单/入账执行
    UPDATE recharge_requests SET pay_order_no = ... 时因列缺失而整体失败。
    本迁移补上这一步，并顺带新增扫码支付（微信 NATIVE 等）所需的 pay_qr_url。

幂等可重入：先 inspect 现有列再决定动作；SQLite / PostgreSQL 通用。

Revision ID: 0007_payment_columns
Revises: 0006_usage_details
Create Date: 2026-10-14
"""

from alembic import op
from sqlalchemy import inspect

revision = "0007_payment_columns"
down_revision = "0006_usage_details"
branch_labels = None
depends_on = None


def _columns(bind, table):
    """返回表列名集合；表不存在返回 None。"""
    insp = inspect(bind)
    if table not in insp.get_table_names():
        return None
    return {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    cols = _columns(bind, "recharge_requests")
    if cols is None:
        # 表尚不存在：全新库由建表逻辑（含 pay_order_no / pay_qr_url）负责创建
        return

    if "bank_order_no" in cols and "pay_order_no" not in cols:
        op.execute("ALTER TABLE recharge_requests RENAME COLUMN bank_order_no TO pay_order_no")
        cols.discard("bank_order_no")
        cols.add("pay_order_no")

    if "pay_channel" not in cols:
        op.execute("ALTER TABLE recharge_requests ADD COLUMN pay_channel TEXT DEFAULT ''")
        cols.add("pay_channel")

    if "pay_order_no" not in cols:
        op.execute("ALTER TABLE recharge_requests ADD COLUMN pay_order_no TEXT")
        cols.add("pay_order_no")

    if "pay_qr_url" not in cols:
        op.execute("ALTER TABLE recharge_requests ADD COLUMN pay_qr_url TEXT")


def downgrade() -> None:
    # 列回删会丢数据（订单号/二维码内容），保留不动
    pass
