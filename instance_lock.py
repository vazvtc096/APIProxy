"""跨平台单实例锁。

背景（历史踩坑）：APIProxy 是单写者模型。数据库初始化阶段（Alembic 迁移 /
smart_init 建表）需要拿 DDL 写锁；若在同一个数据库、同一个端口上误启了第二个
实例，两个进程会各自持有部分锁并互相等待，表现为「双方都卡死、5000 端口永不
监听」。此前只能靠人肉「重启前先 stop 旧实例」避免。

本模块在启动最早阶段（任何 DB 操作之前）申请一把进程级排他锁：
  - 拿不到锁 → 立即失败退出，并打印清晰原因与解决办法，而不是静默互锁；
  - 拿到锁   → 全生命周期持有，进程退出时由 atexit 释放。

实现（无第三方依赖）：
  - POSIX   : fcntl.flock(LOCK_EX | LOCK_NB)
  - Windows : msvcrt.locking(LK_NBLCK)

配置：
  - APIPROXY_LOCK_FILE  覆盖锁文件路径（默认与 SQLite 库同目录 .apiproxy.lock）
  - APIPROXY_ALLOW_MULTI=1  显式跳过加锁（仅供特殊调试；多实例互锁风险自负）
"""
from __future__ import annotations

import atexit
import logging
import os

logger = logging.getLogger(__name__)

# 保持文件句柄引用，防止被 GC 关闭而意外释放锁
_lock_handle = None
_lock_path_used = None


class InstanceLockError(RuntimeError):
    """无法获取实例锁（通常意味着已有实例在运行）。"""


def _default_lock_path() -> str:
    """锁文件默认与 SQLite 数据库同目录，保证「同库即同锁」。"""
    override = os.getenv("APIPROXY_LOCK_FILE")
    if override:
        return override
    try:
        from .configs import DB_PATH
        base = os.path.dirname(os.path.abspath(DB_PATH)) or "."
    except Exception:
        base = "."
    return os.path.join(base, ".apiproxy.lock")


def acquire(lock_path: str | None = None):
    """获取单实例排他锁；失败抛 InstanceLockError。返回文件句柄（持锁期间勿关闭）。

    幂等：同一进程重复调用直接返回既有句柄。
    """
    global _lock_handle, _lock_path_used
    if _lock_handle is not None:
        return _lock_handle

    if os.getenv("APIPROXY_ALLOW_MULTI") == "1":
        logger.warning(
            "APIPROXY_ALLOW_MULTI=1：已跳过单实例锁。多实例共用同一数据库/端口"
            "会导致迁移互锁，仅限特殊调试使用。"
        )
        return None

    path = lock_path or _default_lock_path()
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    fh = open(path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            # 确保文件至少 1 字节，再独占锁定第 0 字节
            fh.seek(0)
            if fh.read(1) == b"":
                fh.seek(0)
                fh.write(b"\0")
                fh.flush()
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        existing = ""
        try:
            fh.seek(0)
            existing = fh.read(64).decode("utf-8", "replace").strip().strip("\x00")
        except Exception:
            pass
        fh.close()
        detail = f" 当前持有者 PID: {existing}" if existing else ""
        raise InstanceLockError(
            f"另一个 APIProxy 实例正在运行，无法获取单实例锁。{detail}\n"
            f"  锁文件: {path}\n"
            f"  解决：先停止旧实例（Ctrl+C / 结束对应 python 进程）再启动；\n"
            f"        确认无旧实例后仍报错，可删除锁文件重试；\n"
            f"        确需并行运行请设环境变量 APIPROXY_ALLOW_MULTI=1（风险自负）。"
        ) from exc

    # 写入 PID 便于排查（POSIX flock 锁整个文件，可安全覆盖；
    # Windows 锁的是第 0 字节，故 PID 从偏移 1 开始写，避免覆盖被锁字节）
    try:
        if os.name == "nt":
            fh.seek(1)
            fh.truncate(1)
            fh.write(f"{os.getpid()}\n".encode())
        else:
            fh.seek(0)
            fh.truncate(0)
            fh.write(f"{os.getpid()}\n".encode())
        fh.flush()
    except Exception:
        pass

    _lock_handle = fh
    _lock_path_used = path
    atexit.register(release)
    logger.info("单实例锁已获取: %s (pid=%s)", path, os.getpid())
    return fh


def release() -> None:
    """释放实例锁（幂等；进程退出时自动调用）。"""
    global _lock_handle, _lock_path_used
    fh = _lock_handle
    if fh is None:
        return
    _lock_handle = None
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        fh.close()
    except Exception:
        pass
    if _lock_path_used:
        logger.info("单实例锁已释放: %s", _lock_path_used)
    _lock_path_used = None
