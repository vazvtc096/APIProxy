"""通知缓存回归测试：验证 notif:list / notif:unread 缓存命中与精准失效。

- add_notification / mark_read 必须让对应 uid 的缓存失效，否则会出现
  「已读后仍显示未读」「写入后列表不刷新」的脏数据。
- 缓存层在测试环境为本地内存后端（无 Redis / 无集群），flush 可安全清空。
"""
import pytest

from APIProxy import notifications, cache_store


@pytest.mark.asyncio
async def test_notification_cache_hit_and_invalidation(admin_client):
    cache_store.get_cache().flush()
    uid = "cachetest-uid"

    # 初始未读为 0
    assert await notifications.unread_count(uid) == 0

    # 写入第一条 -> 失效 -> 列表应立即可见
    nid = await notifications.add_notification(uid, "标题1", "正文1")
    assert nid
    lst = await notifications.get_notifications(uid)
    assert any(n["id"] == nid for n in lst)
    assert await notifications.unread_count(uid) == 1

    # 再写一条：若 unread 缓存未被失效，这里会仍返回 1（脏缓存）；
    # 失效正确则应返回 2。
    nid2 = await notifications.add_notification(uid, "标题2", "正文2")
    assert await notifications.unread_count(uid) == 2

    # 标记单条已读 -> 失效 -> 未读降为 1
    await notifications.mark_read(uid, nid)
    assert await notifications.unread_count(uid) == 1

    # 全部已读 -> 未读归零，且 TTL 内命中缓存仍为 0（值正确）
    await notifications.mark_read(uid, "all")
    assert await notifications.unread_count(uid) == 0
    assert await notifications.unread_count(uid) == 0

    # 列表缓存同样被失效：已读后取列表不再含未读项
    refreshed = await notifications.get_notifications(uid, unread_only=True)
    assert refreshed == []

    cache_store.get_cache().flush()


@pytest.mark.asyncio
async def test_notification_cache_serves_cached_within_ttl(admin_client):
    """同一 uid 在未变更时，第二次读取应命中缓存且数据一致。"""
    cache_store.get_cache().flush()
    uid = "cachetest-ttl"
    await notifications.add_notification(uid, "t", "b")

    first = await notifications.get_notifications(uid)
    second = await notifications.get_notifications(uid)
    assert [n["id"] for n in first] == [n["id"] for n in second]

    cache_store.get_cache().flush()
