"""Alembic 迁移环境：从项目 configs.DB_PATH 读取数据库路径。

用法：
    cd E:/Code/APIProxy
    alembic upgrade head     # 迁移到最新
    alembic current          # 查看当前版本
    alembic revision -m "..." # 新建迁移

初始基线（0001_initial）复用 smart_init.smart_init() 的建表逻辑，
确保与现有幂等建表完全一致、不破坏老部署。
"""

import os
import sys

# 确保能 import 项目包：APIProxy 包的父目录加入 sys.path
# (migrations/env.py -> APIProxy/migrations -> APIProxy -> 父目录)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from sqlalchemy import engine_from_config, pool
from alembic import context

from APIProxy.configs import DB_PATH

config = context.config

# 从 configs.DB_PATH（支持 DB_PATH 环境变量覆盖）构造 SQLAlchemy URL
_sqlite_path = str(DB_PATH).replace("\\", "/")
config.set_main_option("sqlalchemy.url", f"sqlite:///{_sqlite_path}")

# 无 SQLAlchemy 模型（项目用原生 sqlite3），autogenerate 不可用，迁移为手工 SQL
target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
