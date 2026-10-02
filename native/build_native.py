#!/usr/bin/env python3
"""Build the APIProxy native accelerator shared library (C/C++ pillar).

Toolchain detection order:
  1. MinGW-w64 gcc  (preferred on this Windows dev box; present at
     E:/Code/executables/mingw64/bin)
  2. MSVC cl.exe     (via vswhere + vcvars64.bat; needs VS 2022 BuildTools)

Output lands next to this script:
  - Windows: _apx_native.dll
  - Linux:   libapx_native.so
  - macOS:   libapx_native.dylib

Usage:
    python native/build_native.py
The build runs automatically on first import if the library is missing
(see native/__init__.py), but invoking this explicitly is recommended in CI.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "_apx_native.c")


def _dll_name():
    if sys.platform.startswith("win"):
        return "_apx_native.dll"
    if sys.platform == "darwin":
        return "libapx_native.dylib"
    return "libapx_native.so"


def _find_msvc_vcvars():
    vswhere = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if not os.path.exists(vswhere):
        return None
    try:
        out = subprocess.run(
            [vswhere, "-latest", "-products", "*",
             "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
             "-property", "installationPath", "-format", "value"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        if not out:
            return None
        cand = os.path.join(out, "VC", "Auxiliary", "Build", "vcvars64.bat")
        return cand if os.path.exists(cand) else None
    except Exception:
        return None


def build_mingw():
    gcc = shutil.which("gcc") or shutil.which("x86_64-w64-mingw32-gcc")
    if not gcc:
        return None
    out = os.path.join(HERE, _dll_name())
    subprocess.run([gcc, "-shared", "-O2", "-Wall", SRC, "-o", out], check=True)
    return out


def build_msvc():
    vcvars = _find_msvc_vcvars()
    if not vcvars:
        return None
    out = os.path.join(HERE, _dll_name())
    cmd = f'call "{vcvars}" >NUL && cl /LD /O2 /W3 "{SRC}" /Fe:"{out}"'
    subprocess.run(cmd, shell=True, check=True)
    return out


def main():
    if not os.path.exists(SRC):
        print(f"[build_native] source not found: {SRC}", file=sys.stderr)
        return 1
    for builder in (build_mingw, build_msvc):
        try:
            out = builder()
            if out and os.path.exists(out):
                print(f"[build_native] OK -> {out}")
                return 0
        except Exception as e:  # noqa: BLE001
            print(f"[build_native] builder failed: {e}", file=sys.stderr)
    print("[build_native] no usable C toolchain found (gcc/cl). "
          "The app will use the pure-Python fallback.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
