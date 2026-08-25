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

from APIProxy.configs import DB_PATH, DB_TYPE, DATABASE_URL

config = context.config

# Alembic 迁移目标跟随应用 DB_TYPE（sqlite | postgres），避免 DB_TYPE=postgres 时
# Alembic 仍硬编码 SQLite URL 导致两后端 alembic_version/schema 不同步（8/23 迁移根因）。
if DB_TYPE in ("postgres", "postgresql") and DATABASE_URL:
    # SQLAlchemy 2.0 显式指定 psycopg2 驱动，避免默认驱动歧义
    if DATABASE_URL.startswith("postgresql://"):
        _alembic_url = "postgresql+psycopg2://" + DATABASE_URL[len("postgresql://"):]
    elif DATABASE_URL.startswith("postgres://"):
        _alembic_url = "postgresql+psycopg2://" + DATABASE_URL[len("postgres://"):]
    else:
        _alembic_url = DATABASE_URL
else:
    _sqlite_path = str(DB_PATH).replace("\\", "/")
    _alembic_url = f"sqlite:///{_sqlite_path}"
config.set_main_option("sqlalchemy.url", _alembic_url)

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
