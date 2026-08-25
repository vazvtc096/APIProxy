"""冒烟测试（目标 4.3）：复用 selftest 对全部 GET 路由做冒烟探测。

运行方式（二选一）：
  cd E:/Code && python APIProxy/tests/smoke_test.py
  cd E:/Code && python -m APIProxy.tests.smoke_test

退出码：0 = 无 FAIL 端点；1 = 存在 FAIL（真实服务故障）。
建议放到定时任务（如凌晨低峰）运行，发现 5xx 及时告警。
"""
import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main() -> int:
    from APIProxy.app import app
    from APIProxy.__main__ import create_app
    from APIProxy import selftest

    create_app()
    res = asyncio.run(selftest.run_endpoint_selftest(app))
    s = res.get("summary", {})
    print(f"[smoke] total={s.get('total')} ok={s.get('ok')} "
          f"warn={s.get('warn')} fail={s.get('fail')} skip={s.get('skip')}")
    for e in res.get("endpoints", []):
        if e.get("state") == "fail":
            print(f"  FAIL {e.get('path')} http={e.get('status')} {e.get('note', '')}")
    return 1 if s.get("fail") else 0


if __name__ == "__main__":
    sys.exit(main())
