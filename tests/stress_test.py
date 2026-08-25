"""轻量压测脚手架（目标 4.3）。

对指定端点并发发起请求，统计 RPS / 平均延迟 / 错误率。
零外部依赖：默认在进程内用 Quart test_client 并发（适合快速冒烟压测）；
若设置环境变量 STRESS_TARGET=http://127.0.0.1:5000，则改为对该真实实例 urllib 打流。

环境变量：
  STRESS_N=200        总请求数
  STRESS_CONC=20      并发度
  STRESS_PATH=/health 目标路径
  STRESS_TARGET=      真实实例 base URL（留空=进程内）

运行：
  cd E:/Code && python APIProxy/tests/stress_test.py
"""
import asyncio
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


async def _main() -> None:
    n = int(os.getenv("STRESS_N", "200"))
    conc = int(os.getenv("STRESS_CONC", "20"))
    path = os.getenv("STRESS_PATH", "/health")
    target = os.getenv("STRESS_TARGET", "").rstrip("/")

    sem = asyncio.Semaphore(conc)
    ok = 0
    fail = 0
    lat = []

    async def once():
        nonlocal ok, fail
        async with sem:
            t0 = time.time()
            try:
                if target:
                    import urllib.request
                    req = urllib.request.Request(target + path)
                    with urllib.request.urlopen(req, timeout=10) as r:
                        code = r.status
                else:
                    from APIProxy.app import app
                    from APIProxy.__main__ import create_app
                    create_app()
                    async with app.test_client() as c:
                        resp = await c.get(path)
                        code = resp.status_code
                lat.append(time.time() - t0)
                ok += 1 if 200 <= code < 500 else 0
                if code >= 500:
                    fail += 1
            except Exception:
                fail += 1

    t0 = time.time()
    await asyncio.gather(*(once() for _ in range(n)))
    el = time.time() - t0
    avg = (sum(lat) / len(lat)) * 1000 if lat else 0.0
    print(f"[stress] n={n} conc={conc} path={path} target={target or 'in-process'}")
    print(f"  rps={n / el:.1f}  ok={ok}  fail(family>=500)={fail}  "
          f"avg_lat={avg:.1f}ms  elapsed={el:.2f}s")


if __name__ == "__main__":
    asyncio.run(_main())
