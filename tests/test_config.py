"""配置加载与环境变量覆盖测试。

重点验证 P0-01/P0-04 涉及的环境变量命名规则是否正确生效。
"""

import subprocess
import sys
import os

from APIProxy import configs

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PKG_PARENT = os.path.dirname(_PROJECT_ROOT)


def test_db_path_env_var_takes_effect():
    """DB_PATH 使用裸环境变量（非 APIPROXY_ 前缀），已指向隔离测试库。"""
    assert configs.DB_PATH.endswith("test_users.db")


def test_oauth_jwt_secret_env_var_takes_effect():
    """OAUTH_JWT_SECRET 经 APIPROXY_OAUTH_JWT_SECRET 覆盖后非空。"""
    assert configs.OAUTH_JWT_SECRET == "test-oauth-jwt-secret-0123456789abcdef"


def test_upstream_key_env_naming_rule():
    """上游 API Key 环境变量命名规则：APIPROXY_UPSTREAM_<NAME 大写、- 转 _>_API_KEY。"""
    # 用独立子进程验证，避免污染已加载的 configs 单例
    code = (
        "import sys\n"
        f"sys.path.insert(0, {_PKG_PARENT!r})\n"
        "import os\n"
        "os.environ['APIPROXY_UPSTREAM_DEEPSEEK_MAIN_API_KEY'] = 'sk-test-123'\n"
        "from APIProxy.configs import _resolve_upstream_api_key\n"
        "print(_resolve_upstream_api_key('deepseek-main', ''))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, cwd=_PROJECT_ROOT,
    )
    assert out.stdout.strip() == "sk-test-123", out.stderr


def test_upstream_key_env_naming_with_fallback():
    """配置里已有 key 时优先用配置值，环境变量仅兜底。"""
    code = (
        "import sys\n"
        f"sys.path.insert(0, {_PKG_PARENT!r})\n"
        "from APIProxy.configs import _resolve_upstream_api_key\n"
        "print(_resolve_upstream_api_key('x', 'configured-key'))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, cwd=_PROJECT_ROOT,
    )
    assert out.stdout.strip() == "configured-key", out.stderr
