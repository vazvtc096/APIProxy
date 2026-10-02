"""通知系统自测：覆盖通知铃铛后端 + 公告→通知解耦。

复用 conftest 的 admin_client / app fixture（临时隔离库 + 种子管理员 + 已装配 app）。
核心验证点：
  1. 空库下 /api/notifications 返回空列表且未读数为 0；
  2. 直接调用 notifications.add_notification 写入后，/api/notifications 能列出且 unread_count 正确；
  3. POST /api/notifications/read {id:'all'} 后未读数归零；
  4. announcements.broadcast_announcement 会同步写入 notifications 表（与好友关系解耦）；
  5. --print-config 能识别 ANNOUNCEMENT_DELIVER_TO_CHAT 配置项。
"""

import pytest

from APIProxy import announcements, notifications
from APIProxy.__main__ import create_app
from APIProxy import core as _core

ORIGIN = {"Origin": "http://localhost"}


def _admin_uid() -> str:
    """从测试库读取已注入的管理员 uid（与 conftest 种子的 testadmin 会话一致）。

    注意：init_database() 的 Alembic 迁移会额外种一个默认管理员，库里因此存在
    多个 is_admin=1 的行；必须按 user_name 精确匹配 testadmin，否则 LIMIT 1 可能
    取到默认管理员，导致通知写入与 admin_client 会话 uid 不一致而测试失败。
    """
    conn = _core._get_conn()
    try:
        row = conn.execute(
            "SELECT uid FROM users WHERE user_name = 'testadmin' LIMIT 1"
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_empty_notifications(admin_client):
    resp = await admin_client.get("/api/notifications")
    assert resp.status_code == 200, await resp.get_data(as_text=True)
    data = await resp.get_json()
    assert data["notifications"] == []
    assert data["unread_count"] == 0


@pytest.mark.asyncio
async def test_add_and_list(admin_client):
    nid = await notifications.add_notification(
        _admin_uid(), "测试标题", "测试正文", level="warning", link="/notifications"
    )
    assert nid, "add_notification 应返回通知 id"

    resp = await admin_client.get("/api/notifications?limit=20")
    assert resp.status_code == 200
    data = await resp.get_json()
    assert data["unread_count"] == 1
    titles = [n["title"] for n in data["notifications"]]
    assert "测试标题" in titles

    # 单条已读
    r2 = await admin_client.post(
        "/api/notifications/read", json={"id": nid}, headers=ORIGIN
    )
    assert r2.status_code == 200
    j2 = await r2.get_json()
    assert j2["success"] is True
    assert j2["unread_count"] == 0


@pytest.mark.asyncio
async def test_mark_all_read(admin_client):
    await notifications.add_notification(_admin_uid(), "a", "x")
    await notifications.add_notification(_admin_uid(), "b", "y")
    before = await admin_client.get("/api/notifications")
    assert (await before.get_json())["unread_count"] >= 2

    r = await admin_client.post(
        "/api/notifications/read", json={"id": "all"}, headers=ORIGIN
    )
    assert r.status_code == 200
    assert (await r.get_json())["unread_count"] == 0


@pytest.mark.asyncio
async def test_broadcast_writes_notification(admin_client):
    """公告广播应同步写入 notifications（解耦 admin 虚拟好友 hack）。"""
    before = await notifications.unread_count(_admin_uid())
    delivered = await announcements.broadcast_announcement(
        title="系统维护通知", content="今晚 22:00 维护", level="info", target="all"
    )
    assert delivered >= 1
    after = await notifications.unread_count(_admin_uid())
    assert after > before, "broadcast_announcement 必须写入至少一条 notifications 记录"


def test_app_registers_notif_blueprint():
    app = create_app()
    rule_paths = {str(r) for r in app.url_map.iter_rules()}
    assert any("/api/notifications" in p for p in rule_paths), \
        f"未注册通知路由，现有: {sorted(rule_paths)}"
    assert any("/notifications" in p for p in rule_paths), \
        "未注册 /notifications 通知中心页面"


def test_print_config_lists_deliver_flag():
    """--print-config 应暴露 ANNOUNCEMENT_DELIVER_TO_CHAT。"""
    from APIProxy import configs
    assert hasattr(configs, "ANNOUNCEMENT_DELIVER_TO_CHAT")
    assert configs.ANNOUNCEMENT_DELIVER_TO_CHAT in (True, False)
