"""Console 运维控制台：集群内任意节点的运行时命令分发中心。

设计目标（相对原 RCON）：
  - 去掉「游戏感」的 RCON 命名，统一为 Console（运维控制台）。
  - 复用 core_rcon 中已成熟的业务运维命令（用户 / 充值 / 会话 / API Key /
    白名单等），避免重复 700 行逻辑。
  - 新增「节点 / 集群」维度的运维命令，覆盖运维的方方面面（状态、角色、
    日志级别、缓存、维护模式、封禁、GC、连接、公告等）。
  - 支持在运行时向 LB / 指定 Worker / 全部 Worker 发送命令：每个节点都暴露
    内部端点 /internal/console（本地执行），dispatch() 据此做跨节点转发。

鉴权：
  - /internal/console 仅接受节点间共享密钥（CLUSTER_SECRET 或 RCON_SECRET），
    并拒绝 Worker 节点对外提供（只有 LB / 单机才执行本地命令）。
  - 运维人员经 /api/console/exec 下发命令，复用 RCON 密钥鉴权（见 console_routes）。
"""

import asyncio
import gc
import json
import logging
import urllib.error
import urllib.request

from . import configs
from .core_rcon import _RCON_HANDLERS, _execute_rcon_command_sync

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Console 精细化权限（目标 3.2）
# --------------------------------------------------------------------------- #
# 命令分 3 个层级（数值越大权限越高）：
#   0 = info  只读 / 查询
#   1 = op    非破坏性运维
#   2 = admin 高危 / 破坏性
TIER_INFO = 0
TIER_OP = 1
TIER_ADMIN = 2
TIER_NAMES = {0: "info", 1: "op", 2: "admin"}

# 各命令所需最低层级。未列出的 NODE 命令默认按 op 处理；
# 业务 RCON 命令（在 _RCON_HANDLERS 中）统一用 CONSOLE_RCON_DEFAULT_TIER。
COMMAND_TIERS = {
    # --- info：只读 / 查询 ---
    "whoami": TIER_INFO, "nodes": TIER_INFO, "cluster_status": TIER_INFO,
    "ids_status": TIER_INFO, "ids_rules": TIER_INFO, "ids_events": TIER_INFO,
    "ids_banlist": TIER_INFO,
    "wf_status": TIER_INFO, "wf_categories": TIER_INFO, "wf_policy": TIER_INFO,
    "wf_log": TIER_INFO,
    "bastion_status": TIER_INFO, "bastion_sessions": TIER_INFO,
    "bastion_replay": TIER_INFO, "bastion_pending": TIER_INFO,
    "audit_status": TIER_INFO, "audit_query": TIER_INFO, "audit_stats": TIER_INFO,
    "auth_status": TIER_INFO, "auth_sessions": TIER_INFO, "auth_introspect": TIER_INFO,
    "selftest": TIER_INFO,
    # --- op：非破坏性运维 ---
    "loglevel": TIER_OP, "reload": TIER_OP, "maintenance_off": TIER_OP,
    "unban_ip": TIER_OP, "wf_unblock": TIER_OP, "resume": TIER_OP,
    "audit_export": TIER_OP, "bastion_approve": TIER_OP, "bastion_deny": TIER_OP,
    "auth_revoke": TIER_OP, "ids_unblock": TIER_OP,
    "announce": TIER_OP, "gc": TIER_OP, "connections": TIER_OP,
    # --- admin：高危 / 破坏性 ---
    "flush_cache": TIER_ADMIN, "maintenance_on": TIER_ADMIN,
    "ban_ip": TIER_ADMIN, "ids_block": TIER_ADMIN, "wf_block": TIER_ADMIN,
    "drain": TIER_ADMIN,
}


def _command_required_tier(command: str) -> int:
    """返回某命令执行所需的最低层级。"""
    if command in COMMAND_TIERS:
        return COMMAND_TIERS[command]
    if command in _RCON_HANDLERS:
        return int(getattr(configs, "CONSOLE_RCON_DEFAULT_TIER", TIER_OP))
    return TIER_OP  # 未知命令默认按 op 对待


def console_tier_for_key(key: str) -> int:
    """返回某密钥被授予的最高层级。

    - 受限密钥表（CONSOLE_KEY_TIERS）中的 key → 其指定层级；
    - 主 RCON/Console 密钥（验证通过）→ CONSOLE_MAX_TIER（默认 admin 全权）。
    """
    kt = getattr(configs, "CONSOLE_KEY_TIERS", {}) or {}
    if key and key in kt:
        try:
            return int(kt[key])
        except (TypeError, ValueError):
            pass
    return int(getattr(configs, "CONSOLE_MAX_TIER", TIER_ADMIN))


def check_command_permission(command: str, tier: int) -> tuple:
    """检查密钥层级是否足以执行该命令。返回 (ok, required_tier)。"""
    req = _command_required_tier(command)
    return (tier >= req), req


# --------------------------------------------------------------------------- #
# 节点 / 集群运维命令（新增，覆盖运维的方方面面）
# --------------------------------------------------------------------------- #
def _cmd_whoami(args) -> dict:
    from .cluster import cluster, NODE_ID_HEX
    return {"success": True, "output": f"node_id={NODE_ID_HEX} role={cluster.role}",
            "data": {"node_id": NODE_ID_HEX, "role": cluster.role}}


def _cmd_nodes(args) -> dict:
    from .cluster import cluster
    nodes = cluster.list_nodes()
    lines = [f"集群节点（{len(nodes)} 个）："]
    for n in nodes:
        flag = " *" if n.get("self") else "  "
        drain = " [draining]" if n.get("draining") else ""
        lines.append(f"  {flag} {n['node_id']}  {n['role']:6}  {n.get('host')}:{n.get('port')}{drain}")
    return {"success": True, "output": "\n".join(lines), "data": {"nodes": nodes}}


def _cmd_cluster_status(args) -> dict:
    from .cluster import cluster, NODE_ID_HEX
    info = {
        "node_id": NODE_ID_HEX,
        "role": cluster.role,
        "mode": cluster.mode,
        "transport": getattr(configs, "CLUSTER_TRANSPORT", "?"),
        "enabled": getattr(configs, "CLUSTER_ENABLED", False),
        "lb": cluster.lb_info,
        "peers": len(cluster._peers),
        "draining": cluster._draining,
        "epoch": cluster._lb_epoch if cluster.role == "lb" else 0,
    }
    lines = [f"集群状态：",
             f"  node_id : {info['node_id']}",
             f"  role     : {info['role']} (mode={info['mode']}, transport={info['transport']})",
             f"  lb       : {info['lb']}",
             f"  peers    : {info['peers']}",
             f"  draining : {info['draining']}",
             f"  epoch    : {info['epoch']}"]
    return {"success": True, "output": "\n".join(lines), "data": info}


def _cmd_loglevel(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：loglevel <DEBUG|INFO|WARNING|ERROR>", "data": {}}
    lvl = args[0].upper()
    if lvl not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        return {"success": False, "output": f"非法级别：{lvl}", "data": {}}
    root = logging.getLogger()
    old = logging.getLevelName(root.level)
    root.setLevel(getattr(logging, lvl))
    return {"success": True, "output": f"日志级别 {old} → {lvl}", "data": {"old": old, "new": lvl}}


def _cmd_flush_cache(args) -> dict:
    from . import cache_store
    try:
        n = len(cache_store.get_cache().keys("*"))
    except Exception:
        n = -1
    cache_store.get_cache().flush()
    return {"success": True, "output": f"本地缓存已清空（清理前约 {n} 个键）", "data": {"keys_before": n}}


def _cmd_reload(args) -> dict:
    msgs = []
    try:
        from . import pricing
        rows = pricing.reload_pricing_from_db()
        msgs.append(f"定价表重载 {rows} 行")
    except Exception as e:
        msgs.append(f"定价表重载失败：{e}")
    try:
        from . import upstreams
        asyncio.run(upstreams.startup_refresh())
        msgs.append("上游模型目录刷新完成")
    except Exception as e:
        msgs.append(f"上游刷新失败：{e}")
    return {"success": True, "output": "\n".join(msgs), "data": {}}


def _set_maintenance(on: bool, msg: str) -> dict:
    from .rcon import _set_config
    _set_config("maintenance", "1" if on else "0")
    if msg:
        _set_config("maintenance_msg", msg)
    return {"success": True,
            "output": f"维护模式 {'开启' if on else '关闭'}" + (f"：{msg}" if msg else ""),
            "data": {"maintenance": on, "message": msg}}


def _cmd_maintenance_on(args) -> dict:
    return _set_maintenance(True, " ".join(args))


def _cmd_maintenance_off(args) -> dict:
    return _set_maintenance(False, "")


def _cmd_ban_ip(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：ban_ip <ip> [reason]", "data": {}}
    ip = args[0].strip()
    reason = " ".join(args[1:]) or "operator ban"
    from .core_db import _get_conn
    conn = _get_conn()
    try:
        with conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS ip_blacklist "
                "(ip TEXT PRIMARY KEY, reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
            conn.execute("INSERT OR REPLACE INTO ip_blacklist (ip, reason) VALUES (?, ?)", (ip, reason))
            conn.commit()
        return {"success": True, "output": f"已封禁 IP：{ip}（原因：{reason}）", "data": {"ip": ip}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _cmd_unban_ip(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：unban_ip <ip>", "data": {}}
    ip = args[0].strip()
    from .core_db import _get_conn
    conn = _get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM ip_blacklist WHERE ip = ?", (ip,))
            conn.commit()
        return {"success": True, "output": f"已解封 IP：{ip}", "data": {"ip": ip}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _cmd_gc(args) -> dict:
    collected = gc.collect()
    try:
        import os
        import psutil
        rss = psutil.Process(os.getpid()).memory_info().rss // 1024 // 1024
        mem = f" RSS≈{rss}MB"
    except Exception:
        mem = ""
    return {"success": True, "output": f"GC 回收 {collected} 个对象{mem}",
            "data": {"collected": collected}}


def _cmd_connections(args) -> dict:
    from .core_db import _get_conn
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM sessions WHERE expires_at > datetime('now')")
        active = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(DISTINCT ip_address) AS c FROM login_logs "
                    "WHERE created_at > datetime('now','-1 day')")
        ips = cur.fetchone()["c"]
        return {"success": True,
                "output": f"活跃会话：{active}\n近 24h 登录来源 IP 数：{ips}",
                "data": {"active_sessions": active, "distinct_ips_24h": ips}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _cmd_announce(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：announce <内容>", "data": {}}
    content = " ".join(args)
    from .core_db import _get_conn
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT uid, user_name FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1")
            admin = cur.fetchone()
            sender_uid = admin["uid"] if admin else "system"
            sender_name = admin["user_name"] if admin else "系统"
            cur.execute("SELECT uid, user_name FROM users WHERE uid IS NOT NULL AND uid != ''")
            recipients = cur.fetchall()
            aid = "ann_" + __import__("uuid").uuid4().hex[:12]
            cur.execute(
                "INSERT INTO announcements "
                "(announcement_id, title, content, level, target, sender_uid, sender_name, recipients, created_at) "
                "VALUES (?, ?, ?, 'info', 'all', ?, ?, ?, CURRENT_TIMESTAMP)",
                (aid, content[:60], content, sender_uid, sender_name, len(recipients)))
            for r in recipients:
                cur.execute(
                    "INSERT INTO chat_messages "
                    "(message_id, from_uid, from_name, to_uid, to_name, content, type, status, is_read, announcement_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'announcement', 'sent', 0, ?, CURRENT_TIMESTAMP)",
                    ("msg_" + __import__("uuid").uuid4().hex[:16], sender_uid, sender_name,
                     r["uid"], r["user_name"], content, aid))
                # 同步写入通知铃铛（与好友关系解耦的权威收件箱）
                cur.execute(
                    "INSERT INTO notifications "
                    "(id, user_uid, title, body, level, link, announcement_id, is_read, created_at) "
                    "VALUES (?, ?, ?, ?, 'info', '/notifications', ?, 0, CURRENT_TIMESTAMP)",
                    ("ntf_" + __import__("uuid").uuid4().hex[:14], r["uid"],
                     content[:60] or "系统公告", content, aid))
            conn.commit()
        return {"success": True, "output": f"公告已广播给 {len(recipients)} 人（{aid}）",
                "data": {"announcement_id": aid, "recipients": len(recipients)}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _cmd_drain(args) -> dict:
    from .cluster import cluster
    cluster.set_draining(True)
    return {"success": True, "output": "本节点已进入 drain（LB 应停止路由至此）", "data": {"draining": True}}


def _cmd_resume(args) -> dict:
    from .cluster import cluster
    cluster.set_draining(False)
    return {"success": True, "output": "本节点已恢复（drain 解除）", "data": {"draining": False}}


def _cmd_ids_status(args) -> dict:
    from . import ids_ips
    st = ids_ips.ids_status()
    lines = ["IDS/IPS 状态：",
             f"  启用     : {st['enabled']}",
             f"  模式     : {st['mode']}（detect=仅告警 / prevent=拦截+封禁）",
             f"  严重即封 : {st['ban_on_critical']}",
             f"  封禁时长 : {st['ban_minutes']} 分钟",
             f"  端点扫描 : {st['scan_paths_threshold']} 个不同 404 / {st['scan_window']}s",
             f"  认证暴破 : {st['authfail_threshold']} 次 401/403 / {st['authfail_window']}s",
             f"  封禁分阈 : {st['block_score']}（prevent）/ {st['detect_score']}（detect）",
             f"  参数洪水 : {st['param_flood']}",
             f"  签名规则 : {st['signature_rules']} 条",
             f"  缓存后端 : {st['backend']}"]
    return {"success": True, "output": "\n".join(lines), "data": st}


def _cmd_ids_rules(args) -> dict:
    from . import ids_ips
    rules = ids_ips.ids_rules()
    lines = ["IDS/IPS 规则（签名 + 行为）：", ""]
    for r in rules:
        lines.append(f"  [{r['severity']:8}] {r['name']:20} 分={r['score']}  ({r['type']})")
        lines.append(f"             {r['description']}")
    return {"success": True, "output": "\n".join(lines), "data": {"rules": rules}}


def _cmd_ids_events(args) -> dict:
    from .core_db import _get_conn
    limit = int(args[0]) if args and args[0].isdigit() else 20
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, severity, risk_score, client_ip, details, action_taken, created_at "
            "FROM security_events WHERE event_type='ids_alert' "
            "ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        if not rows:
            return {"success": True, "output": "暂无 IDS/IPS 告警", "data": {"events": []}}
        lines = [f"最近 {len(rows)} 条 IDS/IPS 告警：", ""]
        for r in rows:
            lines.append(f"  #{r['id']} [{r['severity']}] {r['client_ip']} "
                         f"分={r['risk_score']} {r['action_taken']}")
            lines.append(f"      {r['details']}  ({r['created_at']})")
        return {"success": True, "output": "\n".join(lines),
                "data": {"events": [dict(r) for r in rows]}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _cmd_ids_banlist(args) -> dict:
    from .core_db import _get_conn
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT ip, reason, ban_expire_at, created_at FROM ip_blacklist "
                    "ORDER BY created_at DESC")
        rows = cur.fetchall()
        if not rows:
            return {"success": True, "output": "封禁名单为空", "data": {"blacklist": []}}
        lines = [f"IP 封禁名单（{len(rows)} 条）：", ""]
        for r in rows:
            lines.append(f"  {r['ip']:20} 到期={r['ban_expire_at']}  {r['reason']}")
        return {"success": True, "output": "\n".join(lines),
                "data": {"blacklist": [dict(r) for r in rows]}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _cmd_ids_block(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：ids_block <ip> [reason]", "data": {}}
    ip = args[0].strip()
    reason = " ".join(args[1:]) or "operator ban (IDS)"
    from .core_db import _get_conn
    conn = _get_conn()
    try:
        with conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS ip_blacklist "
                "(ip TEXT PRIMARY KEY, reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
            conn.execute("INSERT OR REPLACE INTO ip_blacklist (ip, reason) VALUES (?, ?)", (ip, reason))
        return {"success": True, "output": f"已封禁 IP：{ip}（原因：{reason}）", "data": {"ip": ip}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _cmd_ids_unblock(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：ids_unblock <ip>", "data": {}}
    ip = args[0].strip()
    from .core_db import _get_conn
    conn = _get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM ip_blacklist WHERE ip = ?", (ip,))
        return {"success": True, "output": f"已解封 IP：{ip}", "data": {"ip": ip}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# 上网行为管理 / 堡垒机 / 日志审计 / 认证服务器 运维命令
# --------------------------------------------------------------------------- #
def _run_coro(coro):
    """在 Console 命令（运行于 to_thread 工作线程，无活动事件循环）中执行协程。"""
    return asyncio.run(coro)


def _cmd_wf_status(args) -> dict:
    from . import web_filter
    st = web_filter.wf_status()
    lines = ["上网行为管理状态：",
             f"  启用    : {st['enabled']}",
             f"  模式    : {st['mode']}（monitor=仅记录 / block=拦截违规分类）",
             f"  全量记录: {st['log_all']}",
             f"  管理员豁免: {st['bypass_admin']}",
             f"  封禁分类: {', '.join(st['block_list']) or '(无)'}",
             f"  分类总数: {st['total_categories']}"]
    return {"success": True, "output": "\n".join(lines), "data": st}


def _cmd_wf_categories(args) -> dict:
    from . import web_filter
    cats = web_filter.wf_categories()
    lines = ["上网行为分类（* = 当前封禁）：", ""]
    for c in cats:
        mark = "*" if c["blocked"] else " "
        lines.append(f"  [{mark}] {c['category']:10} {','.join(c['keywords'][:4])}...")
    return {"success": True, "output": "\n".join(lines), "data": {"categories": cats}}


def _cmd_wf_policy(args) -> dict:
    from . import web_filter
    return {"success": True, "output": str(web_filter.wf_policy()), "data": web_filter.wf_policy()}


def _cmd_wf_log(args) -> dict:
    limit = int(args[0]) if args and args[0].isdigit() else 20
    from .core_db import _get_conn
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT id, user_name, client_ip, method, path, category, action, status, created_at "
            "FROM web_access_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        if not rows:
            return {"success": True, "output": "暂无上网行为记录", "data": {"logs": []}}
        lines = [f"最近 {len(rows)} 条上网行为：", ""]
        for r in rows:
            lines.append(f"  #{r['id']} {r['client_ip']:16} {r['method']:4} "
                         f"{r['path'][:40]:40} [{r['category'] or '-'}] {r['action']} {r['status']}")
        return {"success": True, "output": "\n".join(lines),
                "data": {"logs": [dict(r) for r in rows]}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _cmd_wf_block(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：wf_block <category>", "data": {}}
    from . import web_filter
    web_filter.wf_add_block(args[0].strip().lower())
    return {"success": True, "output": f"已加入封禁分类：{args[0]}",
            "data": {"block_list": web_filter._block_list()}}


def _cmd_wf_unblock(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：wf_unblock <category>", "data": {}}
    from . import web_filter
    web_filter.wf_remove_block(args[0].strip().lower())
    return {"success": True, "output": f"已移出封禁分类：{args[0]}",
            "data": {"block_list": web_filter._block_list()}}


def _cmd_bastion_status(args) -> dict:
    from . import bastion
    st = bastion.bastion_status()
    lines = ["堡垒机状态：",
             f"  启用          : {st['enabled']}",
             f"  管理路由记录  : {st['record_admin_routes']}",
             f"  审批工作流    : {st['approval_enabled']}（高危命令需审批）",
             f"  高危命令      : {', '.join(st['risk_commands']) or '(无)'}",
             f"  本进程会话数  : {st['open_sessions']}"]
    return {"success": True, "output": "\n".join(lines), "data": st}


def _cmd_bastion_sessions(args) -> dict:
    limit = int(args[0]) if args and args[0].isdigit() else 20
    from . import bastion
    rows = bastion.list_sessions(limit)
    if not rows:
        return {"success": True, "output": "暂无堡垒机会话", "data": {"sessions": []}}
    lines = [f"堡垒机会话（{len(rows)} 个）：", ""]
    for r in rows:
        lines.append(f"  {r['session_id']}  operator={r['operator']}  "
                     f"cmds={r['command_count']}  {r['started_at']}")
    return {"success": True, "output": "\n".join(lines), "data": {"sessions": rows}}


def _cmd_bastion_replay(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：bastion_replay <session_id>", "data": {}}
    from . import bastion
    rows = bastion.get_session_audit(args[0].strip())
    if not rows:
        return {"success": True, "output": "该会话无审计记录", "data": {"audit": []}}
    lines = [f"会话 {args[0]} 操作回放（{len(rows)} 条）：", ""]
    for r in rows:
        ok = "OK" if r["result_ok"] else "FAIL"
        lines.append(f"  [{r['created_at']}] {r['operator']} {r['command']} {r['args']} -> {ok}")
        if r["output"]:
            lines.append(f"        {str(r['output'])[:200]}")
    return {"success": True, "output": "\n".join(lines), "data": {"audit": rows}}


def _cmd_bastion_pending(args) -> dict:
    from . import bastion
    rows = bastion.pending_approvals()
    if not rows:
        return {"success": True, "output": "无待审批工单", "data": {"pending": []}}
    lines = [f"待审批工单（{len(rows)} 个）：", ""]
    for r in rows:
        lines.append(f"  {r['ticket_id']}  {r['operator']}  {r['command']} {r['args']}  ({r['created_at']})")
    return {"success": True, "output": "\n".join(lines), "data": {"pending": rows}}


def _cmd_bastion_approve(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：bastion_approve <ticket_id> [note]", "data": {}}
    from . import bastion
    note = " ".join(args[1:])
    ok = bastion.approve_ticket(args[0].strip(), "console", note)
    return {"success": ok, "output": ("已批准工单 " if ok else "批准失败（工单不存在或已处理）：") + args[0],
            "data": {"ticket_id": args[0]}}


def _cmd_bastion_deny(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：bastion_deny <ticket_id> [note]", "data": {}}
    from . import bastion
    note = " ".join(args[1:])
    ok = bastion.deny_ticket(args[0].strip(), "console", note)
    return {"success": ok, "output": ("已驳回工单 " if ok else "驳回失败：") + args[0],
            "data": {"ticket_id": args[0]}}


def _cmd_audit_status(args) -> dict:
    from . import audit_server
    st = audit_server.audit_status()
    lines = ["日志审计服务器状态：",
             f"  启用            : {st['enabled']}",
             f"  保留期          : {st['retention_days']} 天",
             f"  Worker→LB 转发  : {st['forward_to_lb']}",
             f"  外发目标        : {st['syslog_target']}",
             f"  本节点          : {st['node_id']}"]
    return {"success": True, "output": "\n".join(lines), "data": st}


def _cmd_audit_query(args) -> dict:
    limit = int(args[0]) if args and args[0].isdigit() else 50
    from . import audit_server
    rows = _run_coro(audit_server.query(limit=limit))
    if not rows:
        return {"success": True, "output": "暂无审计事件", "data": {"events": []}}
    lines = [f"最近 {len(rows)} 条审计事件：", ""]
    for r in rows:
        lines.append(f"  #{r['id']} [{r['severity']}] {r['category']}/{r['event_type']} "
                     f"{r['client_ip'] or ''} {r['user_name'] or ''}")
        lines.append(f"        {r['details']}  ({r['created_at']})")
    return {"success": True, "output": "\n".join(lines), "data": {"events": rows}}


def _cmd_audit_stats(args) -> dict:
    from . import audit_server
    days = int(args[0]) if args and args[0].isdigit() else 7
    stats = _run_coro(audit_server.stats(days))
    return {"success": True, "output": str(stats), "data": stats}


def _cmd_audit_export(args) -> dict:
    fmt = (args[0] if args else "json").lower()
    from . import audit_server
    rows = _run_coro(audit_server.query(limit=5000))
    text = audit_server.export_rows(rows, fmt)
    path = f"audit_export.{fmt}"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return {"success": True, "output": f"已导出 {len(rows)} 条审计到 {path}",
                "data": {"path": path, "count": len(rows)}}
    except Exception as e:
        return {"success": False, "output": f"导出失败：{e}", "data": {}}


def _cmd_auth_status(args) -> dict:
    from . import auth_server
    st = auth_server.auth_status()
    lines = ["认证服务器状态：",
             f"  启用            : {st['enabled']}",
             f"  自省接口        : {st['introspection_enabled']}"]
    return {"success": True, "output": "\n".join(lines), "data": st}


def _cmd_auth_sessions(args) -> dict:
    limit = int(args[0]) if args and args[0].isdigit() else 20
    from . import auth_server
    rows = _run_coro(auth_server.list_sessions(limit))
    if not rows:
        return {"success": True, "output": "暂无活跃会话", "data": {"sessions": []}}
    lines = [f"活跃会话（{len(rows)} 个）：", ""]
    for r in rows:
        lines.append(f"  {r['session_id']}  user={r['user_name']}  ip={r['ip_address']}  "
                     f"exp={r['expires_at']}")
    return {"success": True, "output": "\n".join(lines), "data": {"sessions": rows}}


def _cmd_auth_revoke(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：auth_revoke <session_id>", "data": {}}
    from . import auth_server
    ok = _run_coro(auth_server.revoke_session(args[0].strip()))
    return {"success": ok, "output": ("已吊销会话 " if ok else "吊销失败：") + args[0],
            "data": {"session_id": args[0]}}


def _cmd_auth_introspect(args) -> dict:
    if not args:
        return {"success": False, "output": "用法：auth_introspect <token>", "data": {}}
    from . import auth_server
    res = _run_coro(auth_server.introspect(args[0].strip()))
    return {"success": True, "output": str(res), "data": res}


def _cmd_selftest(args) -> dict:
    """对全部 GET 路由做冒烟自检（目标 4.1）。可跟参数 force 忽略缓存。"""
    from . import selftest
    from .app import app as _app
    force = bool(args and args[0] in ("force", "--force", "-f"))
    if force:
        res = asyncio.run(selftest.run_endpoint_selftest(_app))
    else:
        res = selftest.get_cached_results()
        if not res.get("endpoints"):
            res = asyncio.run(selftest.run_endpoint_selftest(_app))
    s = res.get("summary", {})
    lines = [f"接口自检：total={s.get('total')} ok={s.get('ok')} warn={s.get('warn')} "
             f"fail={s.get('fail')} skip={s.get('skip')}"]
    for e in res.get("endpoints", []):
        if e.get("state") == "fail":
            lines.append(f"  [FAIL] {e['path']} {e.get('status')} {e.get('note', '')}")
    if not res.get("endpoints"):
        lines.append("  （无缓存结果，可加 force 触发）")
    return {"success": True, "output": "\n".join(lines), "data": res}


NODE_HANDLERS = {
    "whoami": _cmd_whoami,
    "nodes": _cmd_nodes,
    "cluster_status": _cmd_cluster_status,
    "loglevel": _cmd_loglevel,
    "flush_cache": _cmd_flush_cache,
    "reload": _cmd_reload,
    "maintenance_on": _cmd_maintenance_on,
    "maintenance_off": _cmd_maintenance_off,
    "ban_ip": _cmd_ban_ip,
    "unban_ip": _cmd_unban_ip,
    "gc": _cmd_gc,
    "connections": _cmd_connections,
    "announce": _cmd_announce,
    "drain": _cmd_drain,
    "resume": _cmd_resume,
    "ids_status": _cmd_ids_status,
    "ids_rules": _cmd_ids_rules,
    "ids_events": _cmd_ids_events,
    "ids_banlist": _cmd_ids_banlist,
    "ids_block": _cmd_ids_block,
    "ids_unblock": _cmd_ids_unblock,
    # 上网行为管理
    "wf_status": _cmd_wf_status,
    "wf_categories": _cmd_wf_categories,
    "wf_policy": _cmd_wf_policy,
    "wf_log": _cmd_wf_log,
    "wf_block": _cmd_wf_block,
    "wf_unblock": _cmd_wf_unblock,
    # 堡垒机
    "bastion_status": _cmd_bastion_status,
    "bastion_sessions": _cmd_bastion_sessions,
    "bastion_replay": _cmd_bastion_replay,
    "bastion_pending": _cmd_bastion_pending,
    "bastion_approve": _cmd_bastion_approve,
    "bastion_deny": _cmd_bastion_deny,
    # 日志审计服务器
    "audit_status": _cmd_audit_status,
    "audit_query": _cmd_audit_query,
    "audit_stats": _cmd_audit_stats,
    "audit_export": _cmd_audit_export,
    # 认证服务器
    "auth_status": _cmd_auth_status,
    "auth_sessions": _cmd_auth_sessions,
    "auth_revoke": _cmd_auth_revoke,
    "auth_introspect": _cmd_auth_introspect,
    # 启动自检 / 监控
    "selftest": _cmd_selftest,
}


# --------------------------------------------------------------------------- #
# 命令执行 + 跨节点分发
# --------------------------------------------------------------------------- #
def console_help_text() -> str:
    lines = ["Console 运维控制台 — 可用命令：", "", "业务运维（复用 RCON 命令集）："]
    lines += [f"  {c}" for c in sorted(_RCON_HANDLERS.keys())]
    lines += ["", "节点 / 集群运维："]
    lines += [f"  {c}" for c in sorted(NODE_HANDLERS.keys())]
    lines += ["", "跨节点：命令可带 target 参数，经 /api/console/exec 下发：",
              "  target=self（默认）| lb | worker:<node_id> | all"]
    return "\n".join(lines)


def _run_locally(command: str, args: list) -> dict:
    """在本节点本地执行一条 Console 命令。"""
    if command in _RCON_HANDLERS:
        handler = lambda a: _execute_rcon_command_sync(command, a)
    else:
        handler = NODE_HANDLERS.get(command)
        if handler is None:
            return {"success": False,
                    "output": f"未知命令：{command}\n输入 help 查看（Console 命令需经 /api/console/exec）",
                    "data": {}}

    # 堡垒机：高危命令审批前置检查（需审批且无已批准工单时，自动建单并拒绝执行）
    try:
        from . import bastion
        if bastion._enabled():
            blk = bastion.pre_check_approval(command, "console")
            if blk:
                return blk
    except Exception:
        pass

    try:
        result = handler(args or [])
    except Exception as e:
        result = {"success": False, "output": f"执行出错：{e}", "data": {"error": str(e)}}

    # 堡垒机：记录特权命令（含结果），归入 operator 的堡垒机会话
    try:
        from . import bastion
        if bastion._enabled():
            bastion.record_command("console", command, args, "self", result)
    except Exception:
        pass
    return result


def _internal_secret() -> str:
    return getattr(configs, "CLUSTER_SECRET", "") or getattr(configs, "RCON_SECRET", "")


def _resolve_target_url(target: str):
    """把 target 解析为节点 base URL；self 返回 None（本地执行）。"""
    from .cluster import cluster, NODE_ID_HEX
    target = (target or "self").strip().lower()
    if target in ("self", "local", ""):
        return None
    if target == "lb":
        info = cluster.lb_info or {}
        host = info.get("host") or getattr(cluster, "_lb_connect_host", None)
        if not host:
            return None
        return f"http://{host}:{configs.CLUSTER_LB_PORT}"
    if target.startswith("worker:"):
        nid = target.split(":", 1)[1]
        peer = cluster._peers.get(nid)
        if not peer:
            return False  # 标记：找不到该节点
        return f"http://{peer['host']}:{peer['port']}"
    if target == "all":
        return "ALL"
    return False


def _forward(base_url: str, command: str, args: list) -> dict:
    body = json.dumps({"command": command, "args": args}).encode()
    req = urllib.request.Request(
        base_url + "/internal/console",
        data=body,
        headers={"Content-Type": "application/json", "X-Internal-Secret": _internal_secret()},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"success": False, "output": f"转发被拒（{e.code}）：{e.reason}", "data": {}}
    except Exception as e:
        return {"success": False, "output": f"转发失败：{e}", "data": {}}


def dispatch(command: str, args: list = None, target: str = "self") -> dict:
    """执行一条 Console 命令，支持跨节点下发。

    target:
      self           本节点执行（默认）
      lb             转发到当前 LB
      worker:<id>    转发到指定 Worker
      all            本节点 + 全部已知 Worker 各执行一次，聚合结果
    """
    args = args or []
    url = _resolve_target_url(target)
    if url is None:
        return _run_locally(command, args)
    if url is False:
        return {"success": False, "output": f"无法解析目标节点：{target}", "data": {}}
    if url == "ALL":
        results = [{"node": "self", **_run_locally(command, args)}]
        from .cluster import cluster
        for nid, peer in cluster._peers.items():
            if peer.get("is_lb"):
                continue
            base = f"http://{peer['host']}:{peer['port']}"
            results.append({"node": nid, **_forward(base, command, args)})
        ok = all(r.get("success", False) for r in results)
        return {"success": ok, "output": f"已向 {len(results)} 个节点下发 `{command}`",
                "data": {"results": results}}
    return _forward(url, command, args)


# 异步包装（供 Quart 路由以 asyncio.to_thread 调用）
async def dispatch_async(command: str, args: list = None, target: str = "self") -> dict:
    return await asyncio.to_thread(dispatch, command, args, target)


async def run_locally_async(command: str, args: list = None) -> dict:
    return await asyncio.to_thread(_run_locally, command, args)
