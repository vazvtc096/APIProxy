"""插件包（PluginPackage）：目录形态与 zip 形态的统一抽象。

一个插件在磁盘上有两种等价形态，本模块把它们收敛成同一个对象：

    plugins/DemoPlugin/       目录形态（开发态，改完即生效）
        main.py
        README.md
        LICENSE.md
        plugin.json
        helper.py
        assets/…

    plugins/DemoPlugin.zip    压缩包形态（分发态，直接丢进来即可用）
        DemoPlugin/main.py    （顶层包一层目录与否都能识别）
        DemoPlugin/README.md
        …

包内成员约定（除 main.py 外均可选）：

    main.py            入口模块，必需；历史形态 ``__init__.py`` 仍兼容
    plugin.json        清单：名称/版本/作者/许可证/首页/标签/兼容声明/配置默认值
    README.md          说明文档；未显式声明 description 时取其首段
    LICENSE.md         许可证全文；自动识别常见协议名
    requirements.txt   依赖提示（不自动安装）
    其它任意资源        通过 ``Plugin.read_resource()`` 读取

对外入口只有两个：

    from plugin.core.archive import open_package, iter_packages

    pkg = open_package("plugins/DemoPlugin.zip")   # 自动判定并处理内层前缀
    mod = pkg.import_module()                      # 以独立命名空间导入 main.py
    pkg.read_text("README.md")                     # 读取包内资源
"""
from __future__ import annotations

import importlib.machinery
import json
import logging
import os
import re
import sys
import types
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .exceptions import PluginLoadError

logger = logging.getLogger("apiproxy.plugins")

# 入口查找顺序：main.py 为规范入口，__init__.py 仅为历史形态兜底
ENTRY_NAMES: Tuple[str, ...] = ("main.py", "__init__.py")
MANIFEST_NAMES: Tuple[str, ...] = ("plugin.json", "manifest.json", "plugin.toml")
README_NAMES: Tuple[str, ...] = ("README.md", "readme.md", "README.txt",
                                 "README.rst", "README")
LICENSE_NAMES: Tuple[str, ...] = ("LICENSE.md", "LICENSE.txt", "LICENSE",
                                  "LICENSE.rst", "COPYING")
REQUIREMENTS_NAMES: Tuple[str, ...] = ("requirements.txt",)

# 打包时忽略的噪声目录
IGNORE_DIRS = {"__pycache__", ".git", ".idea", ".vscode", ".mypy_cache",
               ".pytest_cache", "node_modules"}

# 许可证识别：按「匹配串 -> 协议名」顺序，越特殊的放前面
LICENSE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0"),
    ("GNU LESSER GENERAL PUBLIC LICENSE", "LGPL-3.0"),
    ("GNU FREE DOCUMENTATION LICENSE", "GFDL-1.3"),
    ("GNU GENERAL PUBLIC LICENSE", "GPL-3.0"),
    ("APACHE LICENSE", "Apache-2.0"),
    ("MIT LICENSE", "MIT"),
    ("MIT ", "MIT"),
    ("MOZILLA PUBLIC LICENSE", "MPL-2.0"),
    ("MULAN PERMISSIVE SOFTWARE LICENSE", "MulanPSL-2.0"),
    ("MULAN PSL", "MulanPSL-2.0"),
    ("BSD 2-CLAUSE", "BSD-2-Clause"),
    ("BSD 3-CLAUSE", "BSD-3-Clause"),
    ("REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS", "BSD-3-Clause"),
    ("ISC LICENSE", "ISC"),
    ("THE UNLICENSE", "Unlicense"),
    ("CREATIVE COMMONS", "CC0-1.0"),
    ("DO WHAT THE FUCK YOU WANT", "WTFPL"),
    ("ZLIB LICENSE", "Zlib"),
    ("BOOST SOFTWARE LICENSE", "BSL-1.0"),
    ("ECLIPSE PUBLIC LICENSE", "EPL-2.0"),
)


# ============================================================================
# 小工具
# ============================================================================

def _clean_id(text: str) -> str:
    """把任意名字规整成可作 python 标识符的插件 id。"""
    return re.sub(r"\W+", "_", text).strip("_") or "plugin"


def _parse_version(text: str) -> Tuple[int, ...]:
    """把 ``>=1.2`` / ``1.2.3`` 之类的版本串解析成可比较元组。"""
    nums = re.findall(r"\d+", str(text or ""))
    return tuple(int(n) for n in nums[:3]) or (0,)


def _first_paragraph(md: str, limit: int = 200) -> str:
    """从 Markdown 里抽取第一段正文，用作缺省简介。"""
    out: List[str] = []
    for raw in md.splitlines():
        line = raw.strip()
        if not line:
            if out:
                break
            continue
        # 跳过标题、徽章、分隔线
        if line.startswith("#") or line.startswith("---") or line.startswith("==="):
            if out:
                break
            continue
        if line.startswith(("![", "[!", "<p", "</", "<!--", "|")):
            continue
        out.append(line)
        if len(" ".join(out)) > limit:
            break
    text = " ".join(out)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)   # 链接 → 文字
    text = re.sub(r"[`*_~]{1,3}", "", text)                  # 去掉行内标记
    return text.strip()[:limit]


def _detect_license_name(text: str) -> Optional[str]:
    head = text[:2000].upper()
    for needle, name in LICENSE_PATTERNS:
        if needle in head:
            return name
    return None


# ============================================================================
# PluginPackage
# ============================================================================

@dataclass
class PluginPackage:
    """一个待加载插件包（目录或 zip，两者 API 完全一致）。"""

    plugin_id: str                    # 由目录名 / zip 名规整而来，用作配置键与命名空间
    path: str                         # 磁盘路径（目录路径或 zip 文件路径）
    root: str                         # 模块搜索根（目录形态 == path；zip 形态含内层前缀）
    entry: str = "main.py"            # 入口文件名
    fmt: str = "dir"                  # 'dir' | 'zip'
    inner: str = ""                   # zip 形态下统一的包前缀目录，可能为空

    # 运行时状态
    _manifest: Optional[dict] = field(default=None, repr=False, compare=False)
    _readme: Optional[str] = field(default=None, repr=False, compare=False)
    _license: Optional[str] = field(default=None, repr=False, compare=False)
    _module: Optional[types.ModuleType] = field(default=None, repr=False, compare=False)

    # ---- 基本属性 ----
    @property
    def is_zip(self) -> bool:
        return self.fmt == "zip"

    @property
    def module_prefix(self) -> str:
        """该插件独有的模块命名空间前缀，避免多个插件的 main 互相覆盖。"""
        return f"ap_plugin_{_clean_id(self.plugin_id)}"

    @property
    def entry_stem(self) -> str:
        return os.path.splitext(self.entry)[0]

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<PluginPackage {self.plugin_id} [{self.fmt}] {self.path}>"

    # ---- 成员 IO ----
    def _member(self, name: str) -> str:
        """把「包内相对路径」转成 zip 内部名 / 磁盘绝对路径。"""
        name = str(name).replace("\\", "/").lstrip("/")
        if not self.is_zip:
            return os.path.join(self.root, *name.split("/"))
        return "/".join([p for p in (self.inner, name) if p])

    def listdir(self, sub: str = "") -> List[str]:
        """列出包内成员名（相对根目录）。"""
        if not self.is_zip:
            base = os.path.join(self.root, sub) if sub else self.root
            if not os.path.isdir(base):
                return []
            return sorted(os.listdir(base))
        prefix = "/".join([p for p in (self.inner, sub) if p])
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        with zipfile.ZipFile(self.path) as z:
            names = []
            for info in z.infolist():
                n = info.filename
                if not n.startswith(prefix):
                    continue
                rest = n[len(prefix):]
                if not rest or "/" in rest:
                    continue
                names.append(rest)
            return sorted(names)

    def exists(self, name: str) -> bool:
        if not self.is_zip:
            return os.path.isfile(self._member(name))
        with zipfile.ZipFile(self.path) as z:
            try:
                z.getinfo(self._member(name))
                return True
            except KeyError:
                return False

    def read_bytes(self, name: str) -> bytes:
        member = self._member(name)
        if not self.is_zip:
            with open(member, "rb") as f:
                return f.read()
        with zipfile.ZipFile(self.path) as z:
            return z.read(member)

    def read_text(self, name: str, encoding: str = "utf-8") -> str:
        return self.read_bytes(name).decode(encoding, errors="replace")

    def find(self, candidates: Sequence[str]) -> Optional[str]:
        """返回候选名单中第一个真实存在的成员名。"""
        for c in candidates:
            if self.exists(c):
                return c
        return None

    def iter_members(self) -> Iterator[str]:
        """迭代包内全部成员的相对路径（已剔除噪声目录与字节码）。"""
        if not self.is_zip:
            for base, dirs, files in os.walk(self.root):
                dirs[:] = [d for d in dirs
                           if d not in IGNORE_DIRS and not d.startswith(".")]
                for f in files:
                    if f.endswith((".pyc", ".pyo")) or f.startswith("."):
                        continue
                    yield os.path.relpath(os.path.join(base, f),
                                          self.root).replace("\\", "/")
            return

        prefix = f"{self.inner}/" if self.inner else ""
        with zipfile.ZipFile(self.path) as z:
            for info in z.infolist():
                n = info.filename
                if not n.startswith(prefix) or n.endswith("/"):
                    continue
                rest = n[len(prefix):]
                if not rest or any(p in IGNORE_DIRS or p.startswith(".")
                                   for p in rest.split("/")[:-1]):
                    continue
                tail = rest.split("/")[-1]
                if tail.endswith((".pyc", ".pyo")) or tail.startswith("."):
                    continue
                yield rest

    def snapshot_source(self, exts: Sequence[str] = (".py", ".json", ".toml")) -> Dict[str, bytes]:
        """把包内的源码/清单文件读进内存，作为「上一版可用快照」。

        热重载时如果新代码加载失败，可以拿这份快照重建一个临时包并加载回去，
        从而避免插件因为一次语法错误就从应用里彻底消失。
        """
        snap: Dict[str, bytes] = {}
        for member in self.iter_members():
            if not member.lower().endswith(tuple(exts)):
                continue
            try:
                snap[member] = self.read_bytes(member)
            except Exception as e:  # pragma: no cover - 文件正被改写
                logger.debug("快照跳过 %s：%s", member, e)
        return snap

    # ---- 元信息 ----
    @property
    def manifest(self) -> dict:
        """清单内容（plugin.json / plugin.toml），读取失败时返回空 dict。"""
        if self._manifest is None:
            self._manifest = self._load_manifest()
        return self._manifest

    def _load_manifest(self) -> dict:
        name = self.find(MANIFEST_NAMES)
        if not name:
            return {}
        try:
            raw = self.read_text(name)
            if name.endswith(".toml"):
                import tomllib  # Python >= 3.11
                data = tomllib.loads(raw)
                return data.get("plugin", data) or {}
            return json.loads(raw) or {}
        except Exception as e:
            logger.warning("插件 %s 的清单 %s 解析失败：%s", self.plugin_id, name, e)
            return {}

    @property
    def readme_text(self) -> str:
        if self._readme is None:
            name = self.find(README_NAMES)
            self._readme = self.read_text(name) if name else ""
        return self._readme

    @property
    def license_text(self) -> str:
        if self._license is None:
            name = self.find(LICENSE_NAMES)
            self._license = self.read_text(name) if name else ""
        return self._license

    @property
    def requirements(self) -> List[str]:
        name = self.find(REQUIREMENTS_NAMES)
        if not name:
            return list(self.manifest.get("requirements") or [])
        lines = self.read_text(name).splitlines()
        return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]

    @property
    def license_name(self) -> str:
        """清单声明优先，否则从 LICENSE 正文里猜。"""
        declared = self.manifest.get("license")
        if declared:
            return str(declared)
        return _detect_license_name(self.license_text) or ""

    @property
    def description(self) -> str:
        """清单 → README 首段 → 空串。"""
        return str(self.manifest.get("description")
                   or _first_paragraph(self.readme_text) or "")

    def config_defaults(self) -> dict:
        """清单里声明的配置默认值，管理员的 plugins.json 会覆盖它。"""
        cfg = self.manifest.get("config") or self.manifest.get("config_defaults")
        return dict(cfg) if isinstance(cfg, dict) else {}

    # ---- 兼容性检查 ----
    def check_compatibility(self, api_version: str = "1.0.0") -> None:
        """校验 Python 版本 / 插件 API 版本要求，不满足抛 PluginLoadError。"""
        min_py = self.manifest.get("python") or self.manifest.get("requires_python")
        if min_py and not self._python_ok(str(min_py)):
            raise PluginLoadError(
                f"需要 Python {min_py}，当前 {sys.version.split()[0]}")
        min_api = self.manifest.get("min_api") or self.manifest.get("min_core")
        if min_api and _parse_version(min_api) > _parse_version(api_version):
            raise PluginLoadError(
                f"需要插件 API >= {min_api}，当前 {api_version}")

    @staticmethod
    def _python_ok(spec: str) -> bool:
        """支持 ``>=3.9`` / ``3.10`` / ``<3.13`` 这类简单比较符。"""
        m = re.match(r"^\s*(>=|<=|==|>|<)?\s*([0-9.]+)\s*$", spec)
        if not m:
            return True
        op, ver = m.group(1) or ">=", m.group(2)
        cur = sys.version_info[:3]
        want = tuple(int(x) for x in (ver.split(".") + ["0", "0"])[:3])
        return {">=": cur >= want, "<=": cur <= want, "==": cur == want,
                ">": cur > want, "<": cur < want}[op]

    # ---- 导入 ----
    def import_module(self) -> types.ModuleType:
        """以插件私有命名空间导入入口模块。

        做法：为插件合成一个父包（``__path__`` 指向该包的搜索根），再把它当作
        子模块导入。好处是插件内部可以正常使用相对导入（``from .helper import x``），
        且不同插件的 ``main`` 不会在 ``sys.modules`` 里互相覆盖。

        zip 形态下 ``root`` 形如 ``xx.zip/inner``，标准 zipimport 支持这种子路径，
        因此两种形态的导入代码是同一套。
        """
        if self._module is not None:
            return self._module

        prefix = self.module_prefix
        parent = sys.modules.get(prefix)
        if parent is None:
            parent = types.ModuleType(prefix)
            parent.__path__ = [self.root]
            parent.__package__ = prefix
            sys.modules[prefix] = parent

        full = f"{prefix}.{self.entry_stem}"
        try:
            spec = importlib.machinery.PathFinder.find_spec(full, parent.__path__)
            if spec is None or spec.loader is None:
                raise PluginLoadError(f"找不到入口模块：{self.entry}")
            module = importlib.util.module_from_spec(spec)
            module.__package__ = prefix
            sys.modules[full] = module
            spec.loader.exec_module(module)
        except Exception:
            # 导入失败不要把半成品留在 sys.modules 里，否则重试会命中坏模块
            sys.modules.pop(full, None)
            sys.modules.pop(prefix, None)
            raise

        # 追加自己的根目录到 sys.path，使插件内部也能写绝对导入（`import helper`）。
        # 放在末尾，保证标准库 / 项目模块优先级更高，不会被插件里的同名文件顶掉。
        if self.root not in sys.path:
            sys.path.append(self.root)

        self._module = module
        return module

    def purge_modules(self) -> int:
        """从 sys.modules 移除本插件导入过的模块，便于干净重载。返回移除数量。"""
        prefix = self.module_prefix
        keys = [k for k in sys.modules
                if k == prefix or k.startswith(prefix + ".")]
        for k in keys:
            sys.modules.pop(k, None)
        if self.root in sys.path:
            try:
                sys.path.remove(self.root)
            except ValueError:  # pragma: no cover
                pass
        self._module = None
        return len(keys)

    # ---- 描述 ----
    def describe(self) -> Dict[str, Any]:
        """可序列化的包信息（不含 instance）。"""
        return {
            "id": self.plugin_id,
            "format": self.fmt,
            "entry": self.entry,
            "path": self.path,
            "license": self.license_name,
            "homepage": self.manifest.get("homepage", ""),
            "author": self.manifest.get("author", ""),
            "tags": list(self.manifest.get("tags") or []),
            "requirements": self.requirements,
            "has_readme": bool(self.readme_text),
            "has_license": bool(self.license_text),
        }


# ============================================================================
# 工厂：打开 / 遍历
# ============================================================================

def _zip_inner_root(zpath: str) -> str:
    """推断 zip 里的包根目录。

    两种常见打包习惯都要支持：

        DemoPlugin.zip → DemoPlugin/main.py   （带一层同名目录，主流）
        DemoPlugin.zip → main.py              （直接压的内容）

    返回 zip 内部前缀（可能为空串）；找不到入口则抛错。
    """
    with zipfile.ZipFile(zpath) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]

    tops = {n.split("/")[0] for n in names if "/" in n}
    flat = {n.split("/")[0] for n in names if "/" not in n}

    # 1) 入口就在顶层：直接以 zip 根作为搜索根
    if any(t in ENTRY_NAMES for t in flat):
        return ""

    # 2) 只有一层顶层目录：深入一层再找（最多下探 3 层，防打包工具多套一层）
    prefix = ""
    for _ in range(3):
        cur = f"{prefix}/" if prefix else ""
        remain = {n[len(cur):] for n in names if n.startswith(cur)} if cur else set(names)
        next_tops = {n.split("/")[0] for n in remain if "/" in n}
        next_flat = {n.split("/")[0] for n in remain if "/" not in n}
        if any(t in ENTRY_NAMES for t in next_flat):
            return prefix
        if len(next_tops) == 1:
            prefix = f"{cur}{next(iter(next_tops))}" if cur else next(iter(next_tops))
            continue
        break

    raise PluginLoadError(f"压缩包中找不到入口文件（{'/'.join(ENTRY_NAMES)}）：{zpath}")


def open_package(path: str, plugin_id: Optional[str] = None) -> PluginPackage:
    """打开一个插件包，自动识别目录 / zip 两种形态。"""
    path = os.path.abspath(path)
    if os.path.isdir(path):
        entry = next((e for e in ENTRY_NAMES if os.path.isfile(os.path.join(path, e))), None)
        if entry is None:
            raise PluginLoadError(f"插件目录缺少入口文件 main.py：{path}")
        pid = plugin_id or os.path.basename(path.rstrip(os.sep))
        return PluginPackage(plugin_id=_clean_id(pid), path=path, root=path,
                             entry=entry, fmt="dir")

    if os.path.isfile(path) and zipfile.is_zipfile(path):
        inner = _zip_inner_root(path)
        root = os.path.join(path, inner) if inner else path
        pid = plugin_id or os.path.splitext(os.path.basename(path))[0]
        return PluginPackage(plugin_id=_clean_id(pid), path=path, root=root,
                             entry="main.py", fmt="zip", inner=inner)

    raise PluginLoadError(f"不是合法的插件包（目录或 .zip）：{path}")


def package_from_snapshot(plugin_id: str,
                          snapshot: Dict[str, bytes],
                          dest: Optional[str] = None) -> PluginPackage:
    """用内存里的源码快照重建一个临时插件包（目录形态）。

    热重载回滚用：新代码加载失败时，把上一版源码写到一个临时目录再加载，
    既不影响用户磁盘上的文件，也能让插件继续对外服务。
    """
    import tempfile

    base = dest or os.path.join(tempfile.mkdtemp(prefix="apx_plugin_"), plugin_id)
    os.makedirs(base, exist_ok=True)
    for member, data in snapshot.items():
        safe = os.path.normpath(os.path.join(base, member.replace("/", os.sep)))
        if not safe.startswith(os.path.abspath(base) + os.sep):  # 防穿越
            continue
        os.makedirs(os.path.dirname(safe), exist_ok=True)
        with open(safe, "wb") as f:
            f.write(data)
    return PluginPackage(plugin_id=_clean_id(plugin_id), path=base, root=base,
                         entry="main.py", fmt="dir")


def iter_packages(plugins_dir: str) -> List[PluginPackage]:
    """遍历插件目录，返回所有可加载的插件包（按 id 排序）。

    跳过以下划线 / 点开头的条目（`.disabled/`、`_tmp/` 之类）。
    """
    found: List[PluginPackage] = []
    if not os.path.isdir(plugins_dir):
        logger.warning("插件目录不存在：%s", plugins_dir)
        return found

    for name in sorted(os.listdir(plugins_dir)):
        if name.startswith(("_", ".")):
            continue
        full = os.path.join(plugins_dir, name)
        is_dir = os.path.isdir(full)
        is_zip = os.path.isfile(full) and name.lower().endswith(".zip")
        if not (is_dir or is_zip):
            continue
        if is_dir and not any(os.path.isfile(os.path.join(full, e)) for e in ENTRY_NAMES):
            # 插件目录里常放些 README / assets 之类，缺入口的静默跳过即可
            logger.debug("目录 %s 中没有入口文件，非插件，跳过", full)
            continue
        try:
            found.append(open_package(full))
        except PluginLoadError as e:
            logger.warning("跳过非法插件包 %s：%s", name, e)
        except Exception as e:  # pragma: no cover - 防御性
            logger.warning("扫描插件包 %s 出错：%s", name, e)
    return found
