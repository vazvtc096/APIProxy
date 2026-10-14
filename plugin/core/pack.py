"""插件打包 / 解包工具：目录形态 ⇄ zip 分发形态。

两种形态在运行时完全等价（都由 core.archive.PluginPackage 打开），区别只在
使用方式：

    目录形态  开发态。改完代码重启即生效，适合自己写的插件。
    zip 形态  分发态。把 DemoPlugin.zip 丢进 plugins/ 就能用，便于分享与备份。

命令行：

    python -m plugin.core.pack plugins/DemoPlugin
        → plugins/DemoPlugin.zip

    python -m plugin.core.pack plugins/DemoPlugin -o dist/Plugin.zip
        → dist/Plugin.zip

    python -m plugin.core.pack plugins/DemoPlugin.zip --extract plugins/
        → plugins/DemoPlugin/（解包回目录形态）

    python -m plugin.core.pack plugins/DemoPlugin --list
        → 列出将要被打包的文件，不实际写文件
"""
from __future__ import annotations

import argparse
import os
import sys
import zipfile
from typing import Iterable, List, Sequence

from .archive import ENTRY_NAMES, IGNORE_DIRS, open_package
from .exceptions import PluginError

__all__ = ["pack_plugin", "extract_plugin", "list_plugin_files"]


def list_plugin_files(src: str,
                      include_hidden: bool = False) -> List[str]:
    """列出插件目录下的全部相对路径（已剔除噪声目录与字节码）。"""
    src = os.path.abspath(src)
    if not os.path.isdir(src):
        raise PluginError(f"不是插件目录：{src}")

    out: List[str] = []
    for base, dirs, files in os.walk(src):
        rel_dir = os.path.relpath(base, src).replace("\\", "/")
        dirs[:] = sorted(d for d in dirs
                         if d not in IGNORE_DIRS and (include_hidden or not d.startswith(".")))
        for f in sorted(files):
            if f.endswith((".pyc", ".pyo")) or f.startswith(".") and not include_hidden:
                continue
            rel = f if rel_dir == "." else f"{rel_dir}/{f}"
            out.append(rel)
    return sorted(out)


def pack_plugin(src: str, out: str = None, *,
                root_folder: bool = True,
                include_hidden: bool = False,
                extra: Sequence[str] = ()) -> str:
    """把一个插件目录打包成可分发 zip。

    Args:
        src           : 插件目录
        out           : 输出 zip 路径；缺省为 ``<src>.zip``
        root_folder   : 是否在 zip 内保留一层同名顶层目录（兼容主流打包习惯）
        include_hidden: 是否包含以点开头的文件
        extra         : 额外要一并打进去的目录内文件路径

    Returns:
        生成的 zip 绝对路径。
    """
    src = os.path.abspath(src)
    if not os.path.isdir(src):
        raise PluginError(f"不是插件目录：{src}")

    entries = {e for e in ENTRY_NAMES if os.path.isfile(os.path.join(src, e))}
    if not entries:
        raise PluginError(f"缺少入口文件 main.py：{src}")

    out_path = os.path.abspath(out or src.rstrip(os.sep) + ".zip")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    top = os.path.basename(src.rstrip(os.sep)) if root_folder else ""
    files = list_plugin_files(src, include_hidden=include_hidden)
    for e in extra:                       # 去重
        rel = os.path.relpath(os.path.abspath(e), src).replace("\\", "/")
        if rel not in files:
            files.append(rel)

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for rel in files:
            arcname = f"{top}/{rel}" if top else rel
            z.write(os.path.join(src, rel.replace("/", os.sep)), arcname)

    return out_path


def extract_plugin(zip_path: str, dest: str = None, *,
                   strip_root: bool = True) -> str:
    """把插件 zip 解包成目录形态（开发时用得着）。

    Args:
        zip_path  : 插件压缩包
        dest      : 目标父目录；缺省为 zip 所在目录
        strip_root: zip 内含一层同名顶层目录时是否把它剥掉
    """
    zip_path = os.path.abspath(zip_path)
    if not (os.path.isfile(zip_path) and zipfile.is_zipfile(zip_path)):
        raise PluginError(f"不是插件压缩包：{zip_path}")

    pkg = open_package(zip_path)          # 顺带校验入口是否存在
    base = os.path.abspath(dest or os.path.dirname(zip_path))
    target = os.path.join(base, pkg.plugin_id)

    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        prefix = f"{pkg.inner}/" if (strip_root and pkg.inner) else ""
        for info in infos:
            name = info.filename
            if name.startswith(prefix):
                name = name[len(prefix):]
            if not name or name.endswith("/"):
                continue
            # 防目录穿越
            safe = os.path.normpath(os.path.join(target, name.replace("/", os.sep)))
            if not safe.startswith(os.path.abspath(target) + os.sep):
                continue
            if info.is_dir():
                continue
            os.makedirs(os.path.dirname(safe), exist_ok=True)
            with z.open(info) as src_f, open(safe, "wb") as dst_f:
                dst_f.write(src_f.read())

    return target


# ============================================================================
# CLI
# ============================================================================

def _cli(argv: Iterable[str] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m plugin.core.pack",
        description="APIProxy 插件打包 / 解包工具")
    ap.add_argument("target", help="插件目录（打包）或插件 zip（解包）")
    ap.add_argument("-o", "--out", help="输出路径（zip 目标 / 解压目标目录）")
    ap.add_argument("--extract", action="store_true",
                    help="解包模式：把 zip 解压成目录形态")
    ap.add_argument("--list", action="store_true", help="仅列出将打包的文件")
    ap.add_argument("--no-root-folder", action="store_true",
                    help="打包时不在 zip 内保留顶层同名目录")
    args = ap.parse_args(None if argv is None else list(argv))

    try:
        if args.list:
            for rel in list_plugin_files(args.target):
                print(rel)
            return 0
        if args.extract:
            dest = extract_plugin(args.target, args.out)
            print(f"已解包到 {dest}")
            return 0
        out = pack_plugin(args.target, args.out,
                          root_folder=not args.no_root_folder)
        print(f"已打包：{out}")
        return 0
    except PluginError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
