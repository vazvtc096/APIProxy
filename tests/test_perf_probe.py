"""临时性能探针：对比通知/统计接口 冷（flush 缓存，走 DB） vs 热（命中缓存）延迟。

跑完即删，不作为常驻测试。"""
import asyncio
import statistics
import time

import pytest

from APIProxy import cache_store, notifications

OUT = r"E:\Code\APIProxy\_perf_result.txt"


@pytest.mark.asyncio
async def test_cold_vs_warm_latency(admin_client):
    lines = []
    uid = "perftest-uid"
    await notifications.add_notification(uid, "t", "b")

    async def cold_unread():
        cache_store.get_cache().flush()
        t0 = time.perf_counter()
        r = await notifications.unread_count(uid)
        return (time.perf_counter() - t0) * 1000, r

    async def warm_unread():
        t0 = time.perf_counter()
        r = await notifications.unread_count(uid)
        return (time.perf_counter() - t0) * 1000, r

    cold = [ (await cold_unread())[0] for _ in range(5) ]
    warm = [ (await warm_unread())[0] for _ in range(5) ]
    lines.append(f"unread_count   cold={statistics.mean(cold):.1f}ms  warm={statistics.mean(warm):.2f}ms  speedup={statistics.mean(cold)/max(statistics.mean(warm),1e-6):.0f}x")

    # 路由级：/api/notifications 冷 vs 热
    def route_ms():
        t0 = time.perf_counter()
        return (time.perf_counter() - t0) * 1000

    # /api/notifications 稳态：冷（flush）后连续 5 次热请求，取最小（稳态）
    cache_store.get_cache().flush()
    t0 = time.perf_counter(); await admin_client.get("/api/notifications"); cold_route = (time.perf_counter()-t0)*1000
    warm_route = []
    for _ in range(5):
        t0 = time.perf_counter(); await admin_client.get("/api/notifications"); warm_route.append((time.perf_counter()-t0)*1000)
    lines.append(f"/api/notifications  cold={cold_route:.1f}ms  warm_min={min(warm_route):.1f}ms  warm_mean={statistics.mean(warm_route):.1f}ms")

    # /api/notifications/unread（铃铛高频轮询端点）：冷 vs 稳态热
    cache_store.get_cache().flush()
    t0 = time.perf_counter(); await admin_client.get("/api/notifications/unread"); cold_u_route = (time.perf_counter()-t0)*1000
    warm_u_route = []
    for _ in range(5):
        t0 = time.perf_counter(); await admin_client.get("/api/notifications/unread"); warm_u_route.append((time.perf_counter()-t0)*1000
)
    lines.append(f"/api/notifications/unread  cold={cold_u_route:.1f}ms  warm_min={min(warm_u_route):.1f}ms  (未读数缓存命中)")

    # admin/stats 冷 vs 稳态热
    cache_store.get_cache().flush()
    t0 = time.perf_counter(); await admin_client.get("/api/admin/stats"); cold_s = (time.perf_counter()-t0)*1000
    warm_s = []
    for _ in range(5):
        t0 = time.perf_counter(); await admin_client.get("/api/admin/stats"); warm_s.append((time.perf_counter()-t0)*1000)
    lines.append(f"/api/admin/stats  cold={cold_s:.1f}ms  warm_min={min(warm_s):.1f}ms  (聚合查询缓存命中)")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    cache_store.get_cache().flush()
    assert True
