"""管理员路由"""
from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
from ..app import app
from ..core import *
from .. import social, oauth, upstreams, pricing
from .. import hooks as _hooks
from .. import announcements as _ann
from ..apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from ..configs import BASEURL, APIKEY, DEBUG_CONSOLE_ENABLED, DEBUG_CONSOLE_SECRET, SSL_ENABLED, SESSION_SECRET, OAUTH_JWT_SECRET, SMTP_CONFIGURED
from .. import configs
from .. import db
from ..constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from ..cloudflare import get_client_ip as _cf_get_client_ip
from .. import waf as _waf
from .. import cache_store
import re
import asyncio
from .. import tokenpolicy as tokenpolicy_mod
from .. import redeem as redeem_mod
from .. import subscription as _subscription
import json
import datetime

admin_bp = Blueprint('admin', __name__)


# ---------- 管理员操作审计（blueprint 级 after_request 自动落库）----------

# 噪音端点不落库（playground 的测试请求等）
_AUDIT_SKIP_PREFIXES = ('/api/admin/playground', '/api/admin/health-probe-test')
_AUDIT_REDACT_SUBSTR = ('password', 'secret', 'token', 'key', 'credential', 'pass')


def _redact_json(obj, _depth=0):
    """递归脱敏：键名含敏感字样的字段值替换为 [redacted]（防嵌套泄漏）。"""
    if _depth > 4:
        return '...'
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            out[k] = ('[redacted]' if any(s in kl for s in _AUDIT_REDACT_SUBSTR)
                      else _redact_json(v, _depth + 1))
        return out
    if isinstance(obj, (list, tuple)):
        return [_redact_json(x, _depth + 1) for x in obj[:20]]
    return obj


@admin_bp.after_request
async def _audit_admin_write(response):
    """对 admin 蓝图的非 GET API 请求自动写 audit_log（category=admin）。

    event_type 取 "<METHOD> <path>"；请求体做脱敏摘要（含 password/secret/
    token/key/credential 字样的字段值替换为 [redacted]）；2xx 为 low，
    4xx/5xx 为 medium（失败的管理操作同样值得留痕）。任何异常不影响响应。
    """
    try:
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return response
        p = request.path or ''
        if not p.startswith('/api/'):
            return response  # 页面渲染不算操作
        if any(p.startswith(x) for x in _AUDIT_SKIP_PREFIXES):
            return response
        from .. import audit_server
        summary = ''
        try:
            j = await request.get_json(silent=True)
            if isinstance(j, dict):
                summary = json.dumps(_redact_json(j), ensure_ascii=False, default=str)[:600]
        except Exception:
            pass
        sev = 'low' if response.status_code < 400 else 'medium'
        await audit_server.audit_log(
            'admin', f"{request.method} {p}", sev,
            f"status={response.status_code} body={summary}",
            user_name=session.get('user', '') or '',
            client_ip=_cf_get_client_ip() or '',
        )
    except Exception as e:
        logging.error(f"admin audit hook failed: {e}")
    return response


@admin_bp.route('/api/admin/audit', methods=['GET'])
async def api_admin_audit_query():
    """管理员会话查询审计日志（audit_server.query 收口）。fmt=csv 可导出。"""
    err = await _require_admin()
    if err:
        return err
    from .. import audit_server

    def _i(name, d=0):
        try:
            return int(request.args.get(name, d))
        except (TypeError, ValueError):
            return d
    rows = await audit_server.query(
        limit=max(1, min(_i('limit', 100), 5000)),
        category=request.args.get('category', ''),
        event_type=request.args.get('event_type', ''),
        severity=request.args.get('severity', ''),
        client_ip=request.args.get('client_ip', ''),
        user=request.args.get('user', ''),
        days=_i('days', 0),
    )
    fmt = (request.args.get('fmt', '') or '').lower()
    if fmt == 'csv':
        text = audit_server.export_rows(rows, 'csv')
        return Response(text, mimetype='text/csv',
                        headers={'Content-Disposition': 'attachment; filename=admin_audit.csv'})
    return jsonify({'events': rows, 'count': len(rows)}), 200


@admin_bp.route('/api/admin/audit-stats', methods=['GET'])
async def api_admin_audit_stats():
    err = await _require_admin()
    if err:
        return err
    from .. import audit_server
    days = request.args.get('days', 7, type=int)
    return jsonify({'stats': await audit_server.stats(max(1, min(days, 365)))}), 200


@admin_bp.route('/admin/audit', methods=['GET'])
async def admin_audit_page():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_audit.html')


_RE_EPOCH = re.compile(r'^-?\d+(\.\d+)?$')


def _ban_expire_to_epoch(exp):
    """将 ip_blacklist.ban_expire_at 统一成 epoch 秒级浮点。

    兼容两种历史存储：秒级浮点（规范格式）与 ISO 字符串（早版本 ban_ip_auto 误写）。
    无法解析时返回 None（视为永久封禁）。
    """
    if exp is None or exp == '':
        return None
    if isinstance(exp, (int, float)):
        return float(exp)
    s = str(exp).strip()
    if _RE_EPOCH.match(s):
        try:
            return float(s)
        except ValueError:
            return None
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:
        return None

@admin_bp.route('/api/admin/recharge-requests', methods=['GET'])
async def admin_recharge_requests():
    """管理员获取充值请求列表（支持筛选）"""
    err = await _require_admin()
    if err:
        return err
    
    # 获取筛选参数
    status = request.args.get('status', '')
    user_uid = request.args.get('user_uid', '')
    min_amount = request.args.get('min_amount', '')
    max_amount = request.args.get('max_amount', '')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    
    # 构建查询
    sql = "SELECT * FROM recharge_requests WHERE 1=1"
    args = []
    
    if status and status in ['pending', 'approved', 'rejected']:
        sql += " AND status = ?"
        args.append(status)
    
    if user_uid:
        sql += " AND user_uid = ?"
        args.append(user_uid)
    
    if min_amount:
        try:
            sql += " AND amount >= ?"
            args.append(float(min_amount))
        except:
            pass
    
    if max_amount:
        try:
            sql += " AND amount <= ?"
            args.append(float(max_amount))
        except:
            pass
    
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    
    requests = await async_db_query(sql, args)
    
    # 获取总数
    count_sql = "SELECT COUNT(*) as cnt FROM recharge_requests WHERE 1=1"
    count_args = args[:-2]  # 去掉 limit 和 offset
    # 重新构建 count 查询
    count_sql = "SELECT COUNT(*) as cnt FROM recharge_requests WHERE 1=1"
    count_args = []
    if status and status in ['pending', 'approved', 'rejected']:
        count_sql += " AND status = ?"
        count_args.append(status)
    if user_uid:
        count_sql += " AND user_uid = ?"
        count_args.append(user_uid)
    if min_amount:
        try:
            count_sql += " AND amount >= ?"
            count_args.append(float(min_amount))
        except:
            pass
    if max_amount:
        try:
            count_sql += " AND amount <= ?"
            count_args.append(float(max_amount))
        except:
            pass
    
    total_result = await async_db_query(count_sql, count_args)
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'requests': requests,
        'total': total,
        'limit': limit,
        'offset': offset
    })



@admin_bp.route('/api/admin/recharge-requests/<request_id>/approve', methods=['POST'])
async def admin_approve_recharge(request_id):
    """管理员通过充值请求"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    remark = data.get('remark', '')
    
    admin_name = session['user']
    
    # 获取管理员 UID
    admin_users = await async_db_query(
        "SELECT uid FROM users WHERE user_name = ?",
        (admin_name,)
    )
    admin_uid = admin_users[0]['uid'] if admin_users else ''
    
    def _process_approve():
        """在事务中处理：检查状态 -> 更新请求 -> 加余额，原子操作"""
        conn = _get_conn()
        try:
            db.begin_write(conn)
            cur = conn.cursor()
            
            # 查询充值请求
            cur.execute("SELECT * FROM recharge_requests WHERE request_id = ?", (request_id,))
            req = cur.fetchone()
            
            if not req:
                conn.rollback()
                return False, 'Request not found', None
            
            req_dict = dict(req)
            
            # 幂等检查
            if req_dict['status'] == 'approved':
                conn.commit()
                return True, 'Already approved', req_dict
            
            if req_dict['status'] != 'pending':
                conn.rollback()
                return False, f'Request already {req_dict["status"]}', None
            
            # 更新充值请求状态
            cur.execute("""
                UPDATE recharge_requests 
                SET status = 'approved', 
                    admin_uid = ?, 
                    admin_name = ?, 
                    admin_remark = ?,
                    processed_at = CURRENT_TIMESTAMP
                WHERE request_id = ?
            """, (admin_uid, admin_name, remark, request_id))
            
            # 增加用户余额
            cur.execute(
                "UPDATE users SET balence = balence + ? WHERE uid = ?",
                (req_dict['amount'], req_dict['user_uid'])
            )
            
            conn.commit()
            logging.info(f"Recharge approved: {request_id}, amount: {req_dict['amount']}, user: {req_dict['user_name']}")
            return True, 'Approved', req_dict

        except Exception as e:
            conn.rollback()
            logging.error(f"Approve recharge error: {e}")
            return False, str(e), None
        finally:
            conn.close()

    success, msg, req_info = await asyncio.to_thread(_process_approve)

    if success:
        if req_info:
            # 触发钩子事件：充值申请通过
            await fire_event('RECHARGE_APPROVED',
                             trigger_user=admin_uid,
                             target_user=req_info.get('user_uid', ''),
                             amount=req_info.get('amount', 0))
        return jsonify({'message': msg}), 200
    else:
        return jsonify({'error': msg}), 400



@admin_bp.route('/api/admin/recharge-requests/<request_id>/reject', methods=['POST'])
async def admin_reject_recharge(request_id):
    """管理员拒绝充值请求"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    remark = data.get('remark', '')
    
    admin_name = session['user']
    
    # 获取管理员 UID
    admin_users = await async_db_query(
        "SELECT uid FROM users WHERE user_name = ?",
        (admin_name,)
    )
    admin_uid = admin_users[0]['uid'] if admin_users else ''
    
    # 查询充值请求
    requests = await async_db_query(
        "SELECT * FROM recharge_requests WHERE request_id = ?",
        (request_id,)
    )
    
    if not requests:
        return jsonify({'error': 'Request not found'}), 404
    
    req = requests[0]
    
    if req['status'] != 'pending':
        return jsonify({'error': f'Request already {req["status"]}'}), 400
    
    # 更新状态
    await async_db_query("""
        UPDATE recharge_requests 
        SET status = 'rejected', 
            admin_uid = ?, 
            admin_name = ?, 
            admin_remark = ?,
            processed_at = CURRENT_TIMESTAMP
        WHERE request_id = ?
    """, (admin_uid, admin_name, remark, request_id))
    
    logging.info(f"Recharge rejected: {request_id}, user: {req['user_name']}, reason: {remark}")
    
    return jsonify({'message': 'Rejected'}), 200



@admin_bp.route('/api/admin/user/<uid>', methods=['GET'])
async def admin_get_user(uid):
    """管理员通过 UID 查询用户全部信息"""
    err = await _require_admin()
    if err:
        return err
    
    user = await _get_user_by_uid(uid)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 移除敏感信息（密码哈希）
    user.pop('user_password', None)
    
    # 获取用户的充值请求记录
    requests = await async_db_query(
        "SELECT * FROM recharge_requests WHERE user_uid = ? ORDER BY created_at DESC LIMIT 10",
        (uid,)
    )
    
    return jsonify({
        'user': user,
        'recent_requests': requests
    })



@admin_bp.route('/api/admin/user/<uid>/balence', methods=['POST'])
async def admin_adjust_balence(uid):
    """管理员调整用户余额（增加/减少）"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    amount = data.get('amount', 0.0)
    reason = data.get('reason', '')
    
    if not isinstance(amount, (int, float)):
        return jsonify({'error': 'Amount must be a number'}), 400
    
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    current_balence = user.get('balence', 0) or 0
    new_balence = current_balence + amount
    
    # 余额不能为负
    if new_balence < 0:
        return jsonify({'error': 'Balance cannot be negative'}), 400
    
    # 更新余额
    await async_db_query(
        "UPDATE users SET balence = ? WHERE uid = ?",
        (new_balence, uid)
    )
    
    admin_name = session['user']
    logging.info(f"Balance adjusted: user {user['user_name']} (UID: {uid}), "
                 f"change: {amount}, new balence: {new_balence}, "
                 f"by admin: {admin_name}, reason: {reason}")
    
    return jsonify({
        'message': 'Balance adjusted',
        'old_balence': current_balence,
        'new_balence': new_balence,
        'change': amount
    }), 200



@admin_bp.route('/api/admin/user/<uid>/overdraft', methods=['POST'])
async def admin_set_overdraft(uid):
    """管理员设置用户超支限额"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    max_overdraft = data.get('max_overdraft', 0.0)
    
    if not isinstance(max_overdraft, (int, float)):
        return jsonify({'error': 'max_overdraft must be a number'}), 400
    
    if max_overdraft < 0:
        return jsonify({'error': 'max_overdraft cannot be negative'}), 400
    
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 更新超支限额
    await async_db_query(
        "UPDATE users SET max_overdraft = ? WHERE uid = ?",
        (max_overdraft, uid)
    )
    
    admin_name = session['user']
    logging.info(f"Overdraft limit set: user {user['user_name']} (UID: {uid}), "
                 f"max_overdraft: {max_overdraft}, by admin: {admin_name}")
    
    return jsonify({
        'message': 'Overdraft limit updated',
        'uid': uid,
        'username': user['user_name'],
        'max_overdraft': max_overdraft
    }), 200



@admin_bp.route('/api/admin/user/<uid>/ban', methods=['POST'])
async def admin_ban_user(uid):
    """管理员封禁用户"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    reason = data.get('reason', '')
    expire_at = data.get('expire_at', '')  # ISO 格式时间，为空表示永久
    
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 不能封禁自己
    if user['user_name'] == session['user']:
        return jsonify({'error': 'Cannot ban yourself'}), 400
    
    # 更新封禁状态
    if expire_at:
        await async_db_query("""
            UPDATE users SET is_banned = 1, ban_reason = ?, ban_expire_at = ? WHERE uid = ?
        """, (reason, expire_at, uid))
    else:
        await async_db_query("""
            UPDATE users SET is_banned = 1, ban_reason = ?, ban_expire_at = NULL WHERE uid = ?
        """, (reason, uid))
    
    admin_name = session['user']
    logging.info(f"User banned: {user['user_name']} (UID: {uid}), "
                 f"reason: {reason}, expire: {expire_at or 'permanent'}, "
                 f"by admin: {admin_name}")
    
    return jsonify({'message': 'User banned'}), 200



@admin_bp.route('/api/admin/user/<uid>/unban', methods=['POST'])
async def admin_unban_user(uid):
    """管理员解封用户"""
    err = await _require_admin()
    if err:
        return err
    
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # 更新封禁状态
    await async_db_query("""
        UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expire_at = NULL WHERE uid = ?
    """, (uid,))
    
    admin_name = session['user']
    logging.info(f"User unbanned: {user['user_name']} (UID: {uid}), by admin: {admin_name}")
    
    return jsonify({'message': 'User unbanned'}), 200


# ---------- 管理员：IP 封禁管理 ----------

@admin_bp.route('/api/admin/ip-bans', methods=['GET'])
async def admin_list_ip_bans():
    """管理员查看 IP 黑名单列表"""
    err = await _require_admin()
    if err:
        return err
    rows = await async_db_query(
        "SELECT id, ip, reason, ban_expire_at, created_at FROM ip_blacklist "
        "ORDER BY id DESC"
    )
    now = time.time()
    result = []
    for r in (rows or []):
        r = dict(r)
        exp = r.get('ban_expire_at')
        epoch = _ban_expire_to_epoch(exp)
        active = (epoch is None) or (epoch > now)
        result.append({
            'id': r['id'],
            'ip': r['ip'],
            'reason': r.get('reason') or '',
            'ban_expire_at': epoch,
            'created_at': r.get('created_at'),
            'active': bool(active),
        })
    return jsonify({'ip_bans': result}), 200



@admin_bp.route('/api/admin/ip-bans', methods=['POST'])
async def admin_add_ip_ban():
    """管理员新增 IP 封禁（duration_hours 为空表示永久）"""
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    ip = (data.get('ip') or '').strip()
    reason = (data.get('reason') or '').strip()
    duration_hours = data.get('duration_hours')
    if not ip:
        return jsonify({'error': 'ip is required'}), 400
    # 简单格式校验：IPv4 / IPv6 / CIDR
    import re as _re
    if not _re.match(r'^[0-9a-fA-F:.]+(/\d+)?$', ip):
        return jsonify({'error': 'invalid ip format'}), 400
    ban_expire_at = None
    if duration_hours:
        try:
            ban_expire_at = time.time() + float(duration_hours) * 3600
        except (ValueError, TypeError):
            return jsonify({'error': 'duration_hours must be a number'}), 400
    try:
        await async_db_query(
            "INSERT INTO ip_blacklist (ip, reason, ban_expire_at) VALUES (?, ?, ?)",
            (ip, reason, ban_expire_at)
        )
    except Exception as e:
        # 唯一约束冲突视为已存在
        return jsonify({'error': f'ip already banned or db error: {e}'}), 400
    return jsonify({'message': 'IP banned', 'ip': ip, 'ban_expire_at': ban_expire_at}), 200



@admin_bp.route('/api/admin/ip-bans/<int:bid>', methods=['DELETE'])
async def admin_remove_ip_ban(bid):
    """管理员解除 IP 封禁"""
    err = await _require_admin()
    if err:
        return err
    await async_db_query("DELETE FROM ip_blacklist WHERE id = ?", (bid,))
    return jsonify({'message': 'IP ban removed'}), 200


# ---------- IP 白名单（仅 Debug Console 可控制） ----------
import ipaddress as _ipaddress



@admin_bp.route('/api/admin/security-events', methods=['GET'])
async def admin_list_security_events():
    """管理员查看安全事件审计（支持 severity / user / limit 过滤）"""
    err = await _require_admin()
    if err:
        return err
    severity = request.args.get('severity', '').strip()
    user_name = request.args.get('user', '').strip()
    limit = request.args.get('limit', '200').strip()
    try:
        limit = max(1, min(int(limit), 1000))
    except (ValueError, TypeError):
        limit = 200
    sql = ("SELECT id, user_uid, user_name, event_type, severity, risk_score, details, "
           "client_ip, device_info, action_taken, created_at FROM security_events WHERE 1=1")
    args = []
    if severity:
        sql += " AND severity = ?"
        args.append(severity)
    if user_name:
        sql += " AND user_name = ?"
        args.append(user_name)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    rows = await async_db_query(sql, tuple(args))
    events = [dict(r) for r in (rows or [])]
    return jsonify({'security_events': events, 'count': len(events)}), 200



@admin_bp.route('/api/admin/waf/stats', methods=['GET'])
async def admin_waf_stats():
    """管理员查看 WAF / 行为监测概览：拦截计数、自动封禁、Top 违规 IP、近期事件"""
    err = await _require_admin()
    if err:
        return err
    try:
        day = "created_at >= datetime('now', '-1 day')"
        total_waf = await async_db_query(
            f"SELECT COUNT(*) AS c FROM security_events WHERE event_type='waf_block' AND {day}")
        total_ban = await async_db_query(
            f"SELECT COUNT(*) AS c FROM security_events WHERE event_type='behavior_ban' AND {day}")
        top_ips = await async_db_query(
            "SELECT client_ip, COUNT(*) AS c FROM security_events "
            f"WHERE event_type='waf_block' AND {day} GROUP BY client_ip ORDER BY c DESC LIMIT 10")
        recent = await async_db_query(
            "SELECT id, event_type, severity, risk_score, client_ip, details, created_at "
            f"FROM security_events WHERE event_type IN ('waf_block','behavior_ban') "
            "ORDER BY id DESC LIMIT 100")
        return jsonify({
            'waf_blocks_24h': (total_waf[0]['c'] if total_waf else 0),
            'behavior_bans_24h': (total_ban[0]['c'] if total_ban else 0),
            'top_offender_ips': [dict(r) for r in (top_ips or [])],
            'recent_events': [dict(r) for r in (recent or [])],
        }), 200
    except Exception as e:
        logging.error(f"admin_waf_stats failed: {e}")
        return jsonify({'error': 'failed to load waf stats'}), 500



@admin_bp.route('/api/admin/users', methods=['GET'])
async def admin_list_users():
    """管理员获取用户列表"""
    err = await _require_admin()
    if err:
        return err
    
    # 获取查询参数
    search = request.args.get('search', '')
    is_banned = request.args.get('is_banned', '')
    is_admin = request.args.get('is_admin', '')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    
    # 构建查询（系统虚拟用户 UID 池 0~15 不属于可管理用户，列表排除）
    _sys_filter = " AND (uid IS NULL OR uid = '' OR LENGTH(uid) != 12 OR SUBSTR(uid, 1, 11) != '00000000000')"
    sql = "SELECT id, uid, user_name, email, balence, is_admin, is_banned, ban_reason, ban_expire_at, created_at, max_overdraft FROM users WHERE 1=1" + _sys_filter
    args = []
    
    if search:
        sql += " AND (user_name LIKE ? OR uid LIKE ?)"
        args.extend([f'%{search}%', f'%{search}%'])
    
    if is_banned in ['0', '1']:
        sql += " AND is_banned = ?"
        args.append(int(is_banned))
    
    if is_admin in ['0', '1']:
        sql += " AND is_admin = ?"
        args.append(int(is_admin))
    
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    
    users = await async_db_query(sql, args)
    
    # 获取总数（与列表同口径排除系统虚拟用户）
    count_sql = "SELECT COUNT(*) as cnt FROM users WHERE 1=1" + _sys_filter
    count_args = []
    if search:
        count_sql += " AND (user_name LIKE ? OR uid LIKE ?)"
        count_args.extend([f'%{search}%', f'%{search}%'])
    if is_banned in ['0', '1']:
        count_sql += " AND is_banned = ?"
        count_args.append(int(is_banned))
    if is_admin in ['0', '1']:
        count_sql += " AND is_admin = ?"
        count_args.append(int(is_admin))
    
    total_result = await async_db_query(count_sql, count_args)
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'users': users,
        'total': total,
        'limit': limit,
        'offset': offset
    })



@admin_bp.route('/api/admin/stats', methods=['GET'])
async def admin_stats():
    """管理员获取统计数据"""
    err = await _require_admin()
    if err:
        return err

    # 统计为读多写少的全局聚合，短缓存（默认 15s）削减打开统计页的多段 COUNT/SUM 扫描。
    cached = cache_store.cache_get_json('admin:stats')
    if cached is not None:
        return jsonify(cached)

    # 用户总数
    total_users_result = await async_db_query("SELECT COUNT(*) as cnt FROM users")
    total_users = total_users_result[0]['cnt'] if total_users_result else 0
    
    # 管理员数量
    admin_users_result = await async_db_query("SELECT COUNT(*) as cnt FROM users WHERE is_admin = 1")
    admin_users = admin_users_result[0]['cnt'] if admin_users_result else 0
    
    # 封禁用户数量
    banned_users_result = await async_db_query("SELECT COUNT(*) as cnt FROM users WHERE is_banned = 1")
    banned_users = banned_users_result[0]['cnt'] if banned_users_result else 0
    
    # 待处理充值请求
    pending_requests_result = await async_db_query("SELECT COUNT(*) as cnt FROM recharge_requests WHERE status = 'pending'")
    pending_requests = pending_requests_result[0]['cnt'] if pending_requests_result else 0
    
    # 总充值金额（已通过）
    total_recharge_result = await async_db_query("SELECT COALESCE(SUM(amount), 0) as total FROM recharge_requests WHERE status = 'approved'")
    total_recharge = total_recharge_result[0]['total'] if total_recharge_result else 0
    
    # 总余额
    total_balence_result = await async_db_query("SELECT COALESCE(SUM(balence), 0) as total FROM users")
    total_balence = total_balence_result[0]['total'] if total_balence_result else 0
    
    # 总 API Key 数量
    all_apikeys_result = await async_db_query("SELECT apikeys FROM users WHERE apikeys IS NOT NULL AND apikeys != ''")
    total_apikeys = 0
    for row in all_apikeys_result:
        if row['apikeys']:
            total_apikeys += len([k for k in row['apikeys'].split(',') if k.strip()])
    
    payload = {
        'total_users': total_users,
        'admin_users': admin_users,
        'banned_users': banned_users,
        'pending_requests': pending_requests,
        'total_recharge': total_recharge,
        'total_balence': total_balence,
        'total_apikeys': total_apikeys
    }
    cache_store.cache_set_json('admin:stats', payload, ttl=15)
    return jsonify(payload)



@admin_bp.route('/api/admin/stats/user-growth', methods=['GET'])
async def admin_user_growth():
    """管理员获取用户增长趋势数据"""
    err = await _require_admin()
    if err:
        return err
    
    days = request.args.get('days', 7, type=int)
    if days < 1:
        days = 7
    if days > 365:
        days = 365
    
    # 查询最近 N 天的新增用户
    sql = """
        SELECT 
            DATE(created_at) as date,
            COUNT(*) as count
        FROM users
        WHERE created_at >= DATE('now', '-' || ? || ' days')
        GROUP BY DATE(created_at)
        ORDER BY date ASC
    """
    result = await async_db_query(sql, (days,))
    
    # 构建完整的日期序列，填充没有数据的日期
    from datetime import datetime, timedelta
    
    data_map = {}
    if result:
        for row in result:
            data_map[row['date']] = row['count']
    
    dates = []
    counts = []
    
    end_date = datetime.now().date()
    for i in range(days - 1, -1, -1):
        date = end_date - timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        dates.append(date_str)
        counts.append(data_map.get(date_str, 0))
    
    return jsonify({
        'dates': dates,
        'counts': counts,
        'days': days
    })



@admin_bp.route('/api/admin/users', methods=['POST'])
async def admin_create_user():
    """管理员创建用户"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    is_admin = data.get('is_admin', False)
    initial_balence = data.get('balence', 0.0)
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if len(username) > MAX_USERNAME_LENGTH:
        return jsonify({'error': f'Username too long (max {MAX_USERNAME_LENGTH} chars)'}), 400

    # 用户名只允许字母、数字、下划线
    if not _is_safe_username(username):
        return jsonify({'error': 'Username can only contain letters, numbers and underscores'}), 400

    # 密码强度检查
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Password too short (min {MIN_PASSWORD_LENGTH} chars)'}), 400
    if not any(c.isalpha() for c in password):
        return jsonify({'error': 'Password must contain at least one letter'}), 400
    if not any(c.isdigit() for c in password):
        return jsonify({'error': 'Password must contain at least one digit'}), 400
    
    # 邮箱格式检查
    if email:
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Invalid email format'}), 400
        # 检查邮箱是否已被注册
        existing_email = await async_db_query("SELECT user_name FROM users WHERE email = ?", (email,))
        if existing_email:
            return jsonify({'error': 'Email already registered'}), 400
    
    # 检查用户是否已存在
    existing = await async_db_query("SELECT user_name FROM users WHERE user_name = ?", (username,))
    if existing:
        return jsonify({'error': 'User already exists'}), 400
    
    # 创建用户
    password_hash = hash_password(password)
    uid = generate_uid()
    
    if email:
        await async_db_query(
            "INSERT INTO users (user_name, user_password, balence, uid, email, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
            (username, password_hash, initial_balence, uid, email, 1 if is_admin else 0)
        )
    else:
        await async_db_query(
            "INSERT INTO users (user_name, user_password, balence, uid, is_admin) VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, initial_balence, uid, 1 if is_admin else 0)
        )
    
    admin_name = session['user']
    logging.info(f"Admin created user: {username} (UID: {uid}), admin: {admin_name}")
    
    return jsonify({
        'message': 'User created successfully',
        'username': username,
        'uid': uid,
        'email': email,
        'is_admin': is_admin,
        'balence': initial_balence
    }), 201


# ---------- Debug Console 密钥管理（管理员） ----------


@admin_bp.route('/api/admin/debug-console-keys', methods=['GET'])
async def admin_list_debug_console_keys():
    """管理员列出所有 Debug Console 密钥"""
    err = await _require_admin()
    if err:
        return err
    
    keys = await _list_debug_console_keys()
    return jsonify({'keys': keys}), 200



@admin_bp.route('/api/admin/debug-console-keys', methods=['POST'])
async def admin_create_debug_console_key():
    """管理员生成新的 Debug Console 密钥"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    key_name = data.get('name', 'default') if data else 'default'
    
    new_key = await _generate_debug_console_key(key_name)
    
    admin_name = session['user']
    logging.info(f"Admin created Debug Console key: {key_name}, admin: {admin_name}")
    
    return jsonify({
        'message': 'Debug Console key created successfully',
        'key': new_key,  # 只返回一次明文
        'name': key_name
    }), 201



@admin_bp.route('/api/admin/debug-console-keys/<int:key_id>', methods=['DELETE'])
async def admin_revoke_debug_console_key(key_id):
    """管理员撤销 Debug Console 密钥"""
    err = await _require_admin()
    if err:
        return err
    
    success = await _revoke_debug_console_key(key_id)
    if not success:
        return jsonify({'error': 'Debug Console key not found'}), 404
    
    admin_name = session['user']
    logging.info(f"Admin revoked Debug Console key: {key_id}, admin: {admin_name}")
    
    return jsonify({'message': 'Debug Console key revoked successfully'}), 200


# ---------- Debug Console 执行接口 ----------


@admin_bp.route('/api/admin/user/<uid>/email', methods=['PUT'])
async def admin_set_email(uid):
    """管理员设置/修改用户邮箱"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    email = data.get('email', '').strip()
    
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if email:
        # 邮箱格式检查
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Invalid email format'}), 400
        # 检查邮箱是否已被其他用户使用
        existing = await async_db_query("SELECT uid FROM users WHERE email = ? AND uid != ?", (email, uid))
        if existing:
            return jsonify({'error': 'Email already registered'}), 400
    
    # 更新邮箱
    await async_db_query(
        "UPDATE users SET email = ? WHERE uid = ?",
        (email if email else None, uid)
    )
    
    admin_name = session['user']
    logging.info(f"Admin set email for user {user['user_name']} (UID: {uid}): {email}, admin: {admin_name}")
    
    return jsonify({
        'message': 'Email updated successfully',
        'email': email
    }), 200



@admin_bp.route('/api/admin/user/<uid>', methods=['DELETE'])
async def admin_delete_user(uid):
    """管理员删除用户"""
    err = await _require_admin()
    if err:
        return err
    
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # 系统虚拟用户不可删除（UID 池 0~15）
    from ..system_users import is_system_uid as _is_sys_uid
    if _is_sys_uid(uid):
        return jsonify({'error': '系统虚拟用户不可删除'}), 403

    # 不能删除自己
    if user['user_name'] == session['user']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    username = user['user_name']
    
    # 删除用户的充值请求
    await async_db_query("DELETE FROM recharge_requests WHERE user_uid = ?", (uid,))
    
    # 删除用户
    await async_db_query("DELETE FROM users WHERE uid = ?", (uid,))
    
    admin_name = session['user']
    logging.info(f"Admin deleted user: {username} (UID: {uid}), admin: {admin_name}")
    
    return jsonify({'message': 'User deleted successfully'}), 200



@admin_bp.route('/api/admin/user/<uid>/password', methods=['POST'])
async def admin_set_password(uid):
    """管理员修改用户密码"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    new_password = data.get('new_password', '')
    
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # 系统虚拟用户不可改密（防止被赋密码后登录）
    from ..system_users import is_system_uid as _is_sys_uid2
    if _is_sys_uid2(uid):
        return jsonify({'error': '系统虚拟用户不可修改密码'}), 403

    # 密码强度检查
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if not any(c.isalpha() for c in new_password):
        return jsonify({'error': 'Password must contain at least one letter'}), 400
    if not any(c.isdigit() for c in new_password):
        return jsonify({'error': 'Password must contain at least one number'}), 400
    
    # 更新密码
    password_hash = hash_password(new_password)
    await async_db_query(
        "UPDATE users SET user_password = ? WHERE uid = ?",
        (password_hash, uid)
    )
    
    # 踢掉所有会话
    await async_db_query("DELETE FROM sessions WHERE user_uid = ?", (uid,))
    
    admin_name = session['user']
    logging.info(f"Admin changed password for user {user['user_name']} (UID: {uid}), admin: {admin_name}")
    
    return jsonify({'message': 'Password updated successfully'}), 200


@admin_bp.route('/api/admin/user/<uid>/overdraft', methods=['POST'])
async def admin_set_user_overdraft(uid):
    """管理员设置用户超支限额"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    if data is None or 'max_overdraft' not in data:
        return jsonify({'error': 'max_overdraft is required'}), 400
    
    try:
        max_overdraft = float(data['max_overdraft'])
        if max_overdraft < 0:
            max_overdraft = 0.0
    except (ValueError, TypeError):
        return jsonify({'error': 'max_overdraft must be a valid number'}), 400
    
    result = await async_db_query(
        "UPDATE users SET max_overdraft = ? WHERE uid = ?",
        (max_overdraft, uid)
    )
    
    if result == 0:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'success': True, 'message': '超支限额设置成功', 'max_overdraft': max_overdraft})


@admin_bp.route('/api/admin/user/<uid>/budget', methods=['POST'])
async def admin_set_user_budget(uid):
    """管理员设置用户月度消费预算（0 = 不限；同时可重置本月累计）"""
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if 'monthly_budget' not in data:
        return jsonify({'error': 'monthly_budget is required'}), 400
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    from .. import budget as _budget
    ok, e = await asyncio.to_thread(_budget.set_budget, user['user_name'],
                                    data.get('monthly_budget'))
    if not ok:
        return jsonify({'error': e}), 400
    reset = bool(data.get('reset_spent'))
    if reset:
        await async_db_query(
            "UPDATE users SET budget_spent = 0, budget_month = ? WHERE uid = ?",
            (_budget.current_month(), uid))
    return jsonify({'success': True, 'message': '月度预算设置成功',
                    'monthly_budget': float(data.get('monthly_budget') or 0),
                    'reset_spent': reset})




@admin_bp.route('/api/admin/user/<uid>/clear', methods=['POST'])
async def admin_clear_user_data(uid):
    """管理员清除用户数据（API Key、会话、帖子、消息等）"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    clear_types = data.get('types', ['apikeys', 'sessions'])  # 默认清除 API Key 和会话
    
    user = await _get_user_by_uid(uid)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    username = user['user_name']
    cleared = []
    
    # 清除 API Key
    if 'apikeys' in clear_types:
        await async_db_query("UPDATE users SET apikeys = '' WHERE uid = ?", (uid,))
        cleared.append('apikeys')
    
    # 清除会话
    if 'sessions' in clear_types:
        await async_db_query("DELETE FROM sessions WHERE user_uid = ?", (uid,))
        cleared.append('sessions')
    
    # 清除帖子
    if 'posts' in clear_types:
        await async_db_query("DELETE FROM posts WHERE user_uid = ?", (uid,))
        await async_db_query("DELETE FROM post_favorites WHERE user_uid = ?", (uid,))
        cleared.append('posts')
    
    # 清除好友关系
    if 'friends' in clear_types:
        await async_db_query("DELETE FROM friends WHERE user_uid = ? OR friend_uid = ?", (uid, uid))
        cleared.append('friends')
    
    # 清除聊天消息
    if 'messages' in clear_types:
        await async_db_query("DELETE FROM chat_messages WHERE from_uid = ? OR to_uid = ?", (uid, uid))
        cleared.append('messages')
    
    # 清除交易记录
    if 'transactions' in clear_types:
        await async_db_query("DELETE FROM balence_transactions WHERE user_uid = ?", (uid,))
        cleared.append('transactions')
    
    admin_name = session['user']
    logging.info(f"Admin cleared data for user {username} (UID: {uid}): {', '.join(cleared)}, admin: {admin_name}")
    
    return jsonify({
        'message': 'User data cleared successfully',
        'cleared': cleared
    }), 200

# ---------- 社交功能 ----------

# 社交功能限流配置
RATE_LIMITS['post'] = {'window': 60, 'max': 10}       # 发帖：每分钟最多 10 次
RATE_LIMITS['friend'] = {'window': 60, 'max': 20}     # 好友操作：每分钟最多 20 次
RATE_LIMITS['chat'] = {'window': 60, 'max': 60}       # 聊天：每分钟最多 60 次
RATE_LIMITS['transfer'] = {'window': 60, 'max': 10}   # 转账：每分钟最多 10 次

# ---------- 社交功能辅助函数 ----------


@admin_bp.route('/api/admin/posts', methods=['GET'])
async def admin_list_posts():
    """管理员获取帖子列表（待审核等）"""
    err = await _require_admin()
    if err:
        return err
    
    status = request.args.get('status', 'pending')
    page = int(request.args.get('page', 1))
    page_size = min(int(request.args.get('page_size', 20)), 100)
    offset = (page - 1) * page_size
    
    # 构建查询
    sql = "SELECT * FROM posts WHERE 1=1"
    args = []
    
    if status and status in ['pending', 'approved', 'rejected']:
        sql += " AND status = ?"
        args.append(status)
    
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([page_size, offset])
    
    posts = await async_db_query(sql, args)
    
    # 获取总数
    count_sql = "SELECT COUNT(*) as cnt FROM posts WHERE 1=1"
    count_args = []
    if status and status in ['pending', 'approved', 'rejected']:
        count_sql += " AND status = ?"
        count_args.append(status)
    
    total_result = await async_db_query(count_sql, count_args)
    total = total_result[0]['cnt'] if total_result else 0
    
    return jsonify({
        'posts': posts,
        'total': total,
        'page': page,
        'page_size': page_size
    })


@admin_bp.route('/api/admin/posts/<post_id>/approve', methods=['POST'])
async def admin_approve_post(post_id):
    """管理员审核通过帖子"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    remark = data.get('remark', '')
    
    admin_name = session['user']
    
    # 检查帖子是否存在
    posts = await async_db_query(
        "SELECT * FROM posts WHERE post_id = ?",
        (post_id,)
    )
    if not posts:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts[0]
    
    if post['status'] == 'approved':
        return jsonify({'message': 'Already approved'}), 200
    
    if post['status'] != 'pending':
        return jsonify({'error': f'Post already {post["status"]}'}), 400
    
    # 更新状态
    await async_db_query(
        """UPDATE posts 
           SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP, admin_remark = ?
           WHERE post_id = ?""",
        (admin_name, remark, post_id)
    )
    
    logging.info(f"Post approved: {post_id} by admin {admin_name}")
    
    return jsonify({'message': 'Post approved'}), 200


@admin_bp.route('/api/admin/posts/<post_id>/reject', methods=['POST'])
async def admin_reject_post(post_id):
    """管理员拒绝帖子"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json() or {}
    remark = data.get('remark', '')
    
    if not remark:
        return jsonify({'error': 'Rejection reason required'}), 400
    
    admin_name = session['user']
    
    # 检查帖子是否存在
    posts = await async_db_query(
        "SELECT * FROM posts WHERE post_id = ?",
        (post_id,)
    )
    if not posts:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts[0]
    
    if post['status'] != 'pending':
        return jsonify({'error': f'Post already {post["status"]}'}), 400
    
    # 更新状态
    await async_db_query(
        """UPDATE posts 
           SET status = 'rejected', approved_by = ?, admin_remark = ?
           WHERE post_id = ?""",
        (admin_name, remark, post_id)
    )
    
    logging.info(f"Post rejected: {post_id} by admin {admin_name}, reason: {remark}")
    
    return jsonify({'message': 'Post rejected'}), 200

# ---------- 好友系统 API ----------


@admin_bp.route('/api/admin/model-prices', methods=['GET'])
async def admin_list_model_prices():
    # 查看价格对登录用户公开（写操作 POST 仍仅管理员）
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    rows = await async_db_query(
        "SELECT model, input, output, priced FROM model_prices ORDER BY priced ASC, model ASC"
    )
    return jsonify({'model_prices': [
        {'model': r['model'], 'input': r['input'], 'output': r['output'], 'priced': bool(r['priced'])}
        for r in rows
    ]})



@admin_bp.route('/api/admin/model-prices', methods=['POST'])
async def admin_update_model_price():
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    model = (data.get('model') or '').strip()
    try:
        inp = float(data.get('input', 0))
        out = float(data.get('output', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'input/output must be numbers'}), 400
    if not model:
        return jsonify({'error': 'model is required'}), 400
    await async_db_query(
        "INSERT OR REPLACE INTO model_prices (model, input, output, priced) VALUES (?, ?, ?, 1)",
        (model, inp, out),
    )
    return jsonify({'ok': True, 'model': model, 'input': inp, 'output': out})



@admin_bp.route('/api/admin/pricing-config', methods=['GET'])
async def api_admin_pricing_config():
    """完整计费配置（含 schedules 时段定义），供模型价格页展示时段计费（登录用户可见）。"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({'pricing': configs.PRICING or {}}), 200


# ---------- 时段计费 CRUD（DB 持久化，热加载）----------

@admin_bp.route('/api/admin/pricing-schedules', methods=['GET'])
async def api_admin_list_schedules():
    err = await _require_admin()
    if err:
        return err
    rows = await async_db_query(
        'SELECT id, model, "start", "end", input, output, enabled, days FROM pricing_schedules ORDER BY model ASC, "start" ASC'
    )
    out = []
    for r in rows:
        days = None
        try:
            raw = r['days']
            if raw:
                d = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(d, list):
                    days = sorted({int(x) for x in d if 0 <= int(x) <= 6}) or None
        except (ValueError, TypeError, KeyError):
            days = None
        out.append({'id': r['id'], 'model': r['model'], 'start': r['start'], 'end': r['end'],
                    'input': r['input'], 'output': r['output'], 'enabled': bool(r['enabled']),
                    'days': days})
    return jsonify({'schedules': out})


def _parse_schedule_days(data):
    """解析请求里的 days（生效星期列表 0=周一..6=周日）。返回 (json_str, error)。"""
    days = data.get('days')
    if days in (None, []):
        return None, None
    if not isinstance(days, list):
        return None, 'days must be a list'
    try:
        dl = sorted({int(d) for d in days})
    except (TypeError, ValueError):
        return None, 'days must be integers'
    if any(d < 0 or d > 6 for d in dl):
        return None, 'days out of range 0-6'
    return json.dumps(dl), None



@admin_bp.route('/api/admin/pricing-schedules', methods=['POST'])
async def api_admin_create_schedule():
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    model = (data.get('model') or '').strip()
    start = (data.get('start') or '').strip()
    end = (data.get('end') or '').strip()
    if not model or not start or not end:
        return jsonify({'error': 'model/start/end required'}), 400
    try:
        inp = float(data.get('input', 0))
        out = float(data.get('output', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'input/output must be numbers'}), 400
    days_json, derr = _parse_schedule_days(data)
    if derr:
        return jsonify({'error': derr}), 400
    await async_db_query(
        'INSERT OR IGNORE INTO pricing_schedules (model, "start", "end", input, output, enabled, days) VALUES (?, ?, ?, ?, ?, 1, ?)',
        (model, start, end, inp, out, days_json),
    )
    await asyncio.to_thread(pricing.reload_pricing_from_db)
    return jsonify({'ok': True, 'model': model, 'start': start, 'end': end, 'input': inp, 'output': out})



@admin_bp.route('/api/admin/pricing-schedules/<int:sid>', methods=['PUT'])
async def api_admin_update_schedule(sid):
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    model = (data.get('model') or '').strip()
    start = (data.get('start') or '').strip()
    end = (data.get('end') or '').strip()
    if not model or not start or not end:
        return jsonify({'error': 'model/start/end required'}), 400
    try:
        inp = float(data.get('input', 0))
        out = float(data.get('output', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'input/output must be numbers'}), 400
    enabled = 1 if data.get('enabled', True) else 0
    days_json, derr = _parse_schedule_days(data)
    if derr:
        return jsonify({'error': derr}), 400
    await async_db_query(
        'UPDATE pricing_schedules SET model=?, "start"=?, "end"=?, input=?, output=?, enabled=?, days=? WHERE id=?',
        (model, start, end, inp, out, enabled, days_json, sid),
    )
    await asyncio.to_thread(pricing.reload_pricing_from_db)
    return jsonify({'ok': True, 'id': sid})



@admin_bp.route('/api/admin/pricing-schedules/<int:sid>', methods=['DELETE'])
async def api_admin_delete_schedule(sid):
    err = await _require_admin()
    if err:
        return err
    await async_db_query("DELETE FROM pricing_schedules WHERE id=?", (sid,))
    await asyncio.to_thread(pricing.reload_pricing_from_db)
    return jsonify({'ok': True, 'id': sid})


# ---------- 节假日（命中当天全天谷价；DB 为准）----------

@admin_bp.route('/api/admin/pricing-holidays', methods=['GET'])
async def api_admin_list_holidays():
    err = await _require_admin()
    if err:
        return err
    rows = await async_db_query("SELECT day FROM pricing_holidays ORDER BY day ASC")
    return jsonify({'holidays': [r['day'] for r in rows]})


@admin_bp.route('/api/admin/pricing-holidays', methods=['PUT'])
async def api_admin_set_holidays():
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    days = data.get('holidays', [])
    if not isinstance(days, list):
        return jsonify({'error': 'holidays must be a list'}), 400
    clean = []
    for d in days:
        d = str(d).strip()
        if not d:
            continue
        if not (re.fullmatch(r'\d{4}-\d{2}-\d{2}', d) or re.fullmatch(r'\d{2}-\d{2}', d)):
            return jsonify({'error': f'格式错误（需 YYYY-MM-DD 或 MM-DD）：{d}'}), 400
        clean.append(d)
    clean = sorted(set(clean))
    await async_db_query("DELETE FROM pricing_holidays")
    for d in clean:
        await async_db_query("INSERT INTO pricing_holidays (day) VALUES (?)", (d,))
    await asyncio.to_thread(pricing.reload_pricing_from_db)
    return jsonify({'ok': True, 'holidays': clean})


# ---------- 模型映射 / 用户组 / 上游健康 ----------

@admin_bp.route('/api/admin/model-mappings', methods=['GET'])
async def api_admin_list_mappings():
    err = await _require_admin()
    if err:
        return err
    rows = await async_db_query(
        "SELECT id, pattern, upstreams, target_model, enabled FROM model_mappings ORDER BY id ASC")
    from .. import routing as _rt
    return jsonify({'mappings': [dict(r) for r in (rows or [])],
                    'health': _rt.health_snapshot()})


@admin_bp.route('/api/admin/model-mappings', methods=['POST'])
async def api_admin_create_mapping():
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    pattern = str(data.get('pattern') or '').strip()
    target = str(data.get('target_model') or '').strip()
    if not pattern or not target:
        return jsonify({'error': 'pattern 与 target_model 均必填'}), 400
    ups = data.get('upstreams') or []
    if not isinstance(ups, list):
        return jsonify({'error': 'upstreams 必须是列表（空列表=任意上游）'}), 400
    await async_db_query(
        "INSERT INTO model_mappings (pattern, upstreams, target_model, enabled) VALUES (?, ?, ?, ?)",
        (pattern, ','.join(str(u).strip() for u in ups if str(u).strip()),
         target, 1 if data.get('enabled', True) else 0))
    from .. import routing as _rt
    await asyncio.to_thread(_rt.invalidate_mapping_cache)
    return jsonify({'ok': True})


@admin_bp.route('/api/admin/model-mappings/<int:mid>', methods=['PUT'])
async def api_admin_update_mapping(mid):
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    fields, args = [], []
    if 'pattern' in data:
        if not str(data['pattern']).strip():
            return jsonify({'error': 'pattern 不能为空'}), 400
        fields.append('pattern = ?'); args.append(str(data['pattern']).strip())
    if 'upstreams' in data:
        ups = data['upstreams']
        if not isinstance(ups, list):
            return jsonify({'error': 'upstreams 必须是列表'}), 400
        fields.append('upstreams = ?')
        args.append(','.join(str(u).strip() for u in ups if str(u).strip()))
    if 'target_model' in data:
        if not str(data['target_model']).strip():
            return jsonify({'error': 'target_model 不能为空'}), 400
        fields.append('target_model = ?'); args.append(str(data['target_model']).strip())
    if 'enabled' in data:
        fields.append('enabled = ?'); args.append(1 if data['enabled'] else 0)
    if not fields:
        return jsonify({'error': 'no fields to update'}), 400
    args.append(mid)
    await async_db_query(f"UPDATE model_mappings SET {', '.join(fields)} WHERE id = ?", tuple(args))
    from .. import routing as _rt
    await asyncio.to_thread(_rt.invalidate_mapping_cache)
    return jsonify({'ok': True})


@admin_bp.route('/api/admin/model-mappings/<int:mid>', methods=['DELETE'])
async def api_admin_delete_mapping(mid):
    err = await _require_admin()
    if err:
        return err
    await async_db_query("DELETE FROM model_mappings WHERE id = ?", (mid,))
    from .. import routing as _rt
    await asyncio.to_thread(_rt.invalidate_mapping_cache)
    return jsonify({'ok': True})


@admin_bp.route('/api/admin/user-groups', methods=['GET'])
async def api_admin_list_groups():
    err = await _require_admin()
    if err:
        return err
    from .. import user_groups as _ug
    groups = await asyncio.to_thread(_ug.list_groups)
    users = await async_db_query("SELECT user_name, user_group FROM users ORDER BY user_name")
    return jsonify({'groups': groups,
                    'users': [dict(r) for r in (users or [])]})


@admin_bp.route('/api/admin/user-groups', methods=['POST'])
async def api_admin_save_group():
    """创建/更新组。body: {name, allowed_models?: [..], price_multiplier?, note?}"""
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    name = str(data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name 必填'}), 400
    from .. import user_groups as _ug
    try:
        await asyncio.to_thread(
            _ug.upsert_group, name,
            data.get('allowed_models'),
            float(data['price_multiplier']) if data.get('price_multiplier') is not None else None,
            data.get('note'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'ok': True})


@admin_bp.route('/api/admin/user-groups/<gname>', methods=['DELETE'])
async def api_admin_delete_group(gname):
    err = await _require_admin()
    if err:
        return err
    from .. import user_groups as _ug
    try:
        await asyncio.to_thread(_ug.delete_group, gname)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'ok': True})


@admin_bp.route('/api/admin/user-groups/assign', methods=['POST'])
async def api_admin_assign_group():
    """把用户划入组。body: {user, group}"""
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    user = str(data.get('user') or '').strip()
    group = str(data.get('group') or '').strip()
    if not user or not group:
        return jsonify({'error': 'user 与 group 必填'}), 400
    from .. import user_groups as _ug
    try:
        ok = await asyncio.to_thread(_ug.set_user_group, user, group)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    if not ok:
        return jsonify({'error': 'user not found'}), 404
    return jsonify({'ok': True})


@admin_bp.route('/api/admin/upstream-health', methods=['GET'])
async def api_admin_upstream_health():
    err = await _require_admin()
    if err:
        return err
    from .. import routing as _rt
    from .. import configs as _cfg
    return jsonify({'health': _rt.health_snapshot(),
                    'config': _cfg.UPSTREAM_HEALTH})


@admin_bp.route('/api/admin/playground', methods=['POST'])
async def api_admin_playground():
    """内置测试：管理员会话直接发起一次代理请求（照常计费，走映射/负载均衡全链路）。

    body: {endpoint: 'chat'|'completions'|'embeddings', body: {...}}
    """
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    endpoint = data.get('endpoint', 'chat')
    payload = data.get('body') or {}
    if not isinstance(payload, dict) or not payload.get('model'):
        return jsonify({'error': 'body.model 必填'}), 400
    owner = session.get('user')
    from .. import user_groups as _ug
    allowed, reason, mult = _ug.check_model_access(owner, payload['model'])
    if not allowed:
        return jsonify({'error': reason}), 403
    kind = {'chat': 'chat', 'completions': 'completions',
            'embeddings': 'embeddings'}.get(endpoint)
    if kind is None:
        return jsonify({'error': f'unsupported endpoint: {endpoint}'}), 400
    sess_key = type('SessKey', (), {'owner': owner, 'oauth': True})()
    from .openai_extra import _submit as _pg_submit
    if kind == 'chat':
        # chat 走 req_data 结构（messages 必须存在）
        payload.setdefault('messages', [{'role': 'user', 'content': 'ping'}])
        payload.pop('stream', None)
        queue = await task_manager.get_queue(owner)
        future = asyncio.Future()
        task_data = {'stream': False, 'future': future, 'apikey_obj': sess_key,
                     'req_data': payload, 'price_multiplier': mult}
        await queue.put(task_data)
        try:
            result = await future
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logging.error(f"playground chat error for {owner}: {e}")
            return jsonify({'error': 'Service temporarily unavailable'}), 500
    else:
        result, perr = await _pg_submit(payload, kind, sess_key, mult)
        if perr:
            return perr
    # 取最近一条用量日志展示计费明细
    log = await async_db_query(
        "SELECT model, input_tokens, output_tokens, cost, upstream FROM usage_logs "
        "WHERE user_name = ? ORDER BY created_at DESC LIMIT 1", (owner,))
    return jsonify({'result': result, 'last_usage': dict(log[0]) if log else None})


# ---------- 令牌级管控（管理端） ----------
@admin_bp.route('/api/admin/tokens', methods=['GET'])
async def admin_list_tokens():
    """列出全部用户的令牌策略（管理端）"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    if not await _is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    owner = request.args.get('owner')
    try:
        rows = await asyncio.to_thread(tokenpolicy_mod.list_policies, owner)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'tokens': rows})


@admin_bp.route('/api/admin/tokens/<int:key_id>/policy', methods=['POST'])
async def admin_set_token_policy(key_id: int):
    """管理员修改任意令牌策略"""
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    if not await _is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    data = await request.get_json() or {}
    ok, err = await asyncio.to_thread(
        tokenpolicy_mod.set_policy, key_id, None, True,
        label=data.get('label'),
        expires_at=data.get('expires_at'),
        quota=data.get('quota'),
        allowed_models=data.get('allowed_models'),
        ip_whitelist=data.get('ip_whitelist'),
        is_active=data.get('is_active'),
        rpm_limit=data.get('rpm_limit'),
        tpm_limit=data.get('tpm_limit'),
    )
    return (jsonify({'ok': True}) if ok else (jsonify({'error': err}), 400))


# ---------- 兑换码（管理端） ----------
@admin_bp.route('/api/admin/redeem-codes/generate', methods=['POST'])
async def admin_generate_redeem_codes():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    if not await _is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    data = await request.get_json() or {}
    try:
        count = int(data.get('count') or 1)
        amount = float(data.get('amount') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'count/amount must be numeric'}), 400
    try:
        codes = await asyncio.to_thread(
            redeem_mod.generate_codes, count, amount, session['user'],
            data.get('note') or '')
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'ok': True, 'codes': codes, 'count': len(codes),
                    'amount': round(amount, 6)}), 201


@admin_bp.route('/api/admin/redeem-codes', methods=['GET'])
async def admin_list_redeem_codes():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    if not await _is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    status = request.args.get('status', 'all')
    try:
        rows = await asyncio.to_thread(redeem_mod.list_codes, status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'codes': rows})


@admin_bp.route('/api/admin/redeem-codes/<int:code_id>', methods=['DELETE'])
async def admin_delete_redeem_code(code_id: int):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    if not await _is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    ok, err = await asyncio.to_thread(redeem_mod.delete_code, code_id)
    return (jsonify({'ok': True}) if ok else (jsonify({'error': err}), 400))


# ---------- 计费规则管理页 ----------

@admin_bp.route('/admin/redeem')
async def admin_redeem_page():
    """管理员兑换码管理页"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_redeem.html', active_page='redeem')


@admin_bp.route('/admin/pricing')
async def admin_pricing_page():
    """管理员计费规则管理页：基础单价 / 时段峰谷计费 / 节假日"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_pricing.html')


@admin_bp.route('/admin/playground')
async def admin_playground_page():
    """内置测试页：网页直接发起代理请求"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_playground.html')


@admin_bp.route('/dashboard/routing')
async def admin_routing_page():
    """模型路由管理页：模型映射 / 用户组 / 上游健康"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_routing.html')


# ---------- 上游 Key 管理（替代直接改 config.yaml）----------

@admin_bp.route('/api/admin/upstreams', methods=['GET'])
async def api_admin_list_upstreams():
    err = await _require_admin()
    if err:
        return err
    rows = await async_db_query(
        "SELECT name, base_url, api_key, api_keys, priority, enabled, disabled_models FROM upstreams ORDER BY priority ASC, name ASC"
    )
    out = []
    for r in (rows or []):
        key = r['api_key'] or ''
        masked = key if len(key) <= 8 else (key[:6] + '*' * (len(key) - 10) + key[-4:])

        def _mask(k):
            k = k or ''
            return k if len(k) <= 8 else (k[:6] + '*' * (len(k) - 10) + k[-4:])
        extra = r['api_keys'] if 'api_keys' in r.keys() else ''
        extra_list = [x.strip() for x in (extra or '').replace('\n', ',').split(',') if x.strip()]
        out.append({
            'name': r['name'],
            'base_url': r['base_url'],
            'api_key': key,
            'api_key_masked': masked,
            'api_keys': extra_list,
            'api_keys_masked': [_mask(x) for x in extra_list],
            'priority': r['priority'],
            'enabled': bool(r['enabled']),
            'disabled_models': [x for x in (r['disabled_models'] or '').split(',') if x.strip()],
        })
    return jsonify({'upstreams': out}), 200



@admin_bp.route('/api/admin/upstreams', methods=['POST'])
async def api_admin_create_upstream():
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    ups, e = _normalize_upstream_payload(data)
    if e:
        return jsonify({'error': e}), 400
    await async_db_query(
        "INSERT OR REPLACE INTO upstreams (name, base_url, api_key, api_keys, priority, enabled, disabled_models) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ups['name'], ups['base_url'], ups['api_key'], ups.get('api_keys', ''), ups['priority'], 1 if ups['enabled'] else 0, ups['disabled_models'])
    )
    await asyncio.to_thread(upstreams.reload_upstreams_from_db)
    return jsonify({'ok': True, 'upstream': ups}), 200



@admin_bp.route('/api/admin/upstreams/<name>', methods=['PUT'])
async def api_admin_update_upstream(name):
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    existing = await async_db_query("SELECT name, base_url, api_key, api_keys, priority, enabled, disabled_models FROM upstreams WHERE name = ?", (name,))
    if not existing:
        return jsonify({'error': 'upstream not found'}), 404
    cur = existing[0]
    new_name = (data.get('name') or name).strip() or name
    base_url = (data.get('base_url') or cur['base_url'] or '').strip()
    api_key = data.get('api_key')
    api_key = (api_key.strip() if (api_key is not None and api_key != '') else (cur['api_key'] or ''))
    try:
        priority = int(data.get('priority', cur['priority'] if cur['priority'] is not None else 100))
    except (TypeError, ValueError):
        return jsonify({'error': 'priority must be an integer'}), 400
    enabled = data.get('enabled', bool(cur['enabled']) if cur['enabled'] is not None else True)
    dm = data.get('disabled_models')
    if dm is None:
        dm = cur['disabled_models'] or ''
    elif isinstance(dm, list):
        dm = ','.join([str(x).strip() for x in dm if str(x).strip()])
    elif isinstance(dm, str):
        dm = ','.join([x.strip() for x in dm.split(',') if x.strip()])
    else:
        dm = ''
    # 备用密钥池：未传 = 保持不变；传空列表/空串 = 清空
    if 'api_keys' in data:
        ak = data['api_keys']
        if isinstance(ak, list):
            ak = ','.join([str(x).strip() for x in ak if str(x).strip()])
        elif isinstance(ak, str):
            ak = ','.join([x.strip() for x in ak.replace('\n', ',').split(',') if x.strip()])
        else:
            return jsonify({'error': 'api_keys must be a list or comma-separated string'}), 400
    else:
        ak = cur['api_keys'] if 'api_keys' in cur.keys() else ''
    if not base_url or not api_key:
        return jsonify({'error': 'base_url and api_key are required'}), 400
    await async_db_query(
        "UPDATE upstreams SET name=?, base_url=?, api_key=?, api_keys=?, priority=?, enabled=?, disabled_models=? WHERE name=?",
        (new_name, base_url, api_key, ak or '', priority, 1 if enabled else 0, dm, name)
    )
    await asyncio.to_thread(upstreams.reload_upstreams_from_db)
    return jsonify({'ok': True, 'upstream': {'name': new_name, 'base_url': base_url,
                                             'priority': priority, 'enabled': enabled, 'disabled_models': dm}}), 200



@admin_bp.route('/api/admin/upstreams/<name>', methods=['DELETE'])
async def api_admin_delete_upstream(name):
    err = await _require_admin()
    if err:
        return err
    existing = await async_db_query("SELECT name FROM upstreams WHERE name = ?", (name,))
    if not existing:
        return jsonify({'error': 'upstream not found'}), 404
    await async_db_query("DELETE FROM upstreams WHERE name = ?", (name,))
    await asyncio.to_thread(upstreams.reload_upstreams_from_db)
    return jsonify({'ok': True, 'deleted': name}), 200



@admin_bp.route('/api/admin/cloudflare/ips', methods=['GET', 'POST'])
async def admin_cloudflare_ips():
    """查看当前 Cloudflare IP 段状态；POST 触发立即从官方地址拉取最新段"""
    err = await _require_admin()
    if err:
        return err
    from .. import cloudflare as cf
    if request.method == 'POST':
        ok = cf.refresh_cloudflare_ranges()
        status = cf.get_ranges_status()
        status['refreshed'] = ok
        return jsonify(status)
    return jsonify(cf.get_ranges_status())



@admin_bp.route('/admin/posts')
async def admin_posts_page():
    """管理员帖子审核页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    # 检查是否是管理员
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_posts.html')


@admin_bp.route('/admin/tasks')
async def admin_tasks_page():
    """管理员定时任务管理页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    # 检查是否是管理员
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_tasks.html')



@admin_bp.route('/admin/bans')
async def admin_bans_page():
    """管理员封禁管理页面：IP 封禁、玩家封禁、安全事件审计"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_bans.html')


@admin_bp.route('/admin/ip-audit')
async def admin_ip_audit_page():
    """IP 访问审计审批页面（IP_ACCESS_MODE=audit 模式的管理员 UI）"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_ip_audit.html')


@admin_bp.route('/api/admin/ip-audit', methods=['GET'])
async def admin_ip_audit_list():
    """IP 访问申请列表（audit 模式）"""
    err = await _require_admin()
    if err:
        return err
    from .. import ip_audit
    return jsonify({'records': ip_audit.list_records(),
                    'summary': ip_audit.status_summary(),
                    'mode': str(getattr(configs, 'IP_ACCESS_MODE', '') or '')})


@admin_bp.route('/api/admin/ip-audit/<access_id>/approve', methods=['POST'])
async def admin_ip_audit_approve(access_id):
    err = await _require_admin()
    if err:
        return err
    from .. import ip_audit
    payload = await request.get_json(force=True, silent=True) or {}
    token, msg = ip_audit.approve_access(access_id, "admin-web", payload.get('note') or '')
    if not token:
        return jsonify({'error': msg or '批准失败'}), 404 if '不存在' in (msg or '') else 400
    return jsonify({'success': True,
                    'message': f'已批准 {access_id}，访客将在等待页收到加密访问 Token'
                               f'（{ip_audit.status_summary()["token_ttl_hours"]} 小时有效，绑定其 IP）'})


@admin_bp.route('/api/admin/ip-audit/<access_id>/deny', methods=['POST'])
async def admin_ip_audit_deny(access_id):
    err = await _require_admin()
    if err:
        return err
    from .. import ip_audit
    payload = await request.get_json(force=True, silent=True) or {}
    ok, msg = ip_audit.deny_access(access_id, "admin-web", payload.get('note') or '')
    if not ok:
        return jsonify({'error': msg or '操作失败'}), 404 if '不存在' in (msg or '') else 400
    return jsonify({'success': True, 'message': f'已拒绝/吊销 {access_id}'})



@admin_bp.route('/api/admin/ban-rules', methods=['GET'])
async def admin_get_ban_rules():
    """获取当前封禁规则配置"""
    err = await _require_admin()
    if err:
        return err
    from ..security import get_ban_rules
    return jsonify(get_ban_rules()), 200



@admin_bp.route('/api/admin/ban-rules', methods=['PUT'])
async def admin_put_ban_rules():
    """更新并持久化封禁规则配置（触发次数 / 时长表达式均可单独自定义）"""
    err = await _require_admin()
    if err:
        return err
    import json as _json
    from ..security import set_ban_rules
    data = await request.get_json() or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'invalid body'}), 400
    merged = set_ban_rules(data)
    try:
        await async_db_query(
            "INSERT INTO config_kv (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("ban_rules", _json.dumps(merged, ensure_ascii=False))
        )
    except Exception as e:
        logging.error(f"persist ban_rules failed: {e}")
    return jsonify(merged), 200


# ---------------------------------------------------------------- 用量统计 API

@admin_bp.route('/api/admin/stats/usage-daily', methods=['GET'])
async def api_admin_usage_daily():
    """平台级每日用量趋势（管理员）"""
    err = await _require_admin()
    if err:
        return err
    days = request.args.get('days', 30, type=int)
    days = max(1, min(days, 365))
    return jsonify({'days': days, 'daily': await _usage_daily(days=days),
                    'models_daily': await _usage_daily_by_model(days=days)}), 200



@admin_bp.route('/api/admin/stats/model-usage', methods=['GET'])
async def api_admin_model_usage():
    """平台级模型用量分布（管理员）"""
    err = await _require_admin()
    if err:
        return err
    days = request.args.get('days', 30, type=int)
    days = max(1, min(days, 365))
    rows = await async_db_query(
        """SELECT model, COUNT(*) as requests, COALESCE(SUM(cost), 0) as cost,
                  COALESCE(SUM(total_tokens), 0) as tokens
           FROM usage_logs
           WHERE created_at >= DATE('now', '-' || ? || ' days')
           GROUP BY model ORDER BY cost DESC LIMIT 30""",
        (days,)
    ) or []
    return jsonify({'days': days, 'models': [
        {'model': r['model'], 'requests': r['requests'],
         'cost': round(float(r['cost'] or 0), 6), 'tokens': r['tokens']} for r in rows
    ]}), 200


@admin_bp.route('/api/admin/stats/top-users', methods=['GET'])
async def api_admin_top_users():
    """用户用量排行 TOP N（管理员；按费用降序）"""
    err = await _require_admin()
    if err:
        return err
    days = request.args.get('days', 30, type=int)
    days = max(1, min(days, 365))
    limit = request.args.get('limit', 10, type=int)
    limit = max(1, min(limit, 50))
    rows = await async_db_query(
        """SELECT user_name, COUNT(*) as requests, COALESCE(SUM(cost), 0) as cost,
                  COALESCE(SUM(total_tokens), 0) as tokens
           FROM usage_logs
           WHERE created_at >= DATE('now', '-' || ? || ' days')
           GROUP BY user_name ORDER BY cost DESC LIMIT ?""",
        (days, limit)
    ) or []
    return jsonify({'days': days, 'users': [
        {'user_name': r['user_name'], 'requests': r['requests'],
         'cost': round(float(r['cost'] or 0), 6), 'tokens': r['tokens']} for r in rows
    ]}), 200


@admin_bp.route('/api/admin/stats/upstream-latency', methods=['GET'])
async def api_admin_upstream_latency():
    """上游延迟分位（管理员；Prometheus 直方图，进程生命周期累计）"""
    err = await _require_admin()
    if err:
        return err
    from ..utils.metrics import upstream_latency_summary
    return jsonify({'latencies': upstream_latency_summary()}), 200


@admin_bp.route('/api/admin/stats/billing-calibration', methods=['GET'])
async def api_admin_billing_calibration():
    """计费校准报表（管理员）：字符估算 token（/3 口径）vs 上游真实 token。

    全站计费按字符（1 token ≈ 3 字符近似），上游返回的真实 usage 落在
    real_prompt_tokens / real_completion_tokens。本报表按模型对比两者，
    偏差率 = (估算 - 真实) / 真实，为后续按 token 计价提供数据依据。
    仅统计捕获到真实 usage 的行（real_* 非 NULL）。
    """
    err = await _require_admin()
    if err:
        return err
    days = request.args.get('days', 30, type=int)
    days = max(1, min(days, 365))
    rows = await async_db_query(
        """SELECT model, COUNT(*) as requests,
                  COALESCE(SUM(input_tokens), 0) as in_chars,
                  COALESCE(SUM(output_tokens), 0) as out_chars,
                  COALESCE(SUM(CASE WHEN real_prompt_tokens IS NOT NULL
                              THEN real_prompt_tokens ELSE 0 END), 0) as real_in,
                  COALESCE(SUM(CASE WHEN real_completion_tokens IS NOT NULL
                              THEN real_completion_tokens ELSE 0 END), 0) as real_out,
                  COALESCE(SUM(CASE WHEN real_reasoning_tokens IS NOT NULL
                              THEN real_reasoning_tokens ELSE 0 END), 0) as reasoning,
                  COALESCE(SUM(CASE WHEN real_cache_hit_tokens IS NOT NULL
                              THEN real_cache_hit_tokens ELSE 0 END), 0) as cache_hit,
                  SUM(CASE WHEN real_prompt_tokens IS NOT NULL THEN 1 ELSE 0 END) as captured
           FROM usage_logs
           WHERE created_at >= DATE('now', '-' || ? || ' days')
           GROUP BY model ORDER BY requests DESC LIMIT 100""",
        (days,)
    ) or []
    out = []
    for r in rows:
        est_tokens = (int(r['in_chars'] or 0) + int(r['out_chars'] or 0)) / 3.0
        real_in = int(r['real_in'] or 0)
        real_out = int(r['real_out'] or 0)
        real_tokens = real_in + real_out
        dev = None
        if real_tokens > 0:
            dev = round((est_tokens - real_tokens) / real_tokens * 100.0, 1)
        cache_hit = int(r['cache_hit'] or 0)
        reasoning = int(r['reasoning'] or 0)
        out.append({
            'model': r['model'], 'requests': r['requests'],
            'in_chars': int(r['in_chars'] or 0), 'out_chars': int(r['out_chars'] or 0),
            'est_tokens': int(round(est_tokens)),
            'real_in': real_in, 'real_out': real_out,
            'real_tokens': real_tokens, 'captured': int(r['captured'] or 0),
            'deviation_pct': dev,
            'cache_hit': cache_hit,
            'cache_hit_pct': round(cache_hit / real_in * 100.0, 1) if real_in > 0 else None,
            'reasoning': reasoning,
            'reasoning_pct': round(reasoning / real_out * 100.0, 1) if real_out > 0 else None,
        })
    return jsonify({'days': days, 'models': out}), 200


@admin_bp.route('/api/admin/stats/usage-export', methods=['GET'])
async def api_admin_usage_export():
    """导出每日用量明细 CSV（管理员；含每日聚合与用户/模型排行三段）"""
    err = await _require_admin()
    if err:
        return err
    days = request.args.get('days', 30, type=int)
    days = max(1, min(days, 365))
    daily = await _usage_daily(days=days)
    lines = ['date,requests,tokens,cost']
    for i, d in enumerate(daily['dates']):
        lines.append(f"{d},{daily['requests'][i]},{daily['tokens'][i]},{daily['costs'][i]}")
    # 用户排行
    urows = await async_db_query(
        """SELECT user_name, COUNT(*) as requests, COALESCE(SUM(cost), 0) as cost,
                  COALESCE(SUM(total_tokens), 0) as tokens
           FROM usage_logs
           WHERE created_at >= DATE('now', '-' || ? || ' days')
           GROUP BY user_name ORDER BY cost DESC LIMIT 100""",
        (days,)
    ) or []
    lines.append('')
    lines.append('user,requests,tokens,cost')
    for r in urows:
        lines.append(f"{r['user_name']},{r['requests']},{r['tokens']},{round(float(r['cost'] or 0), 6)}")
    # 模型排行
    mrows = await async_db_query(
        """SELECT model, COUNT(*) as requests, COALESCE(SUM(cost), 0) as cost,
                  COALESCE(SUM(total_tokens), 0) as tokens
           FROM usage_logs
           WHERE created_at >= DATE('now', '-' || ? || ' days')
           GROUP BY model ORDER BY cost DESC LIMIT 100""",
        (days,)
    ) or []
    lines.append('')
    lines.append('model,requests,tokens,cost')
    for r in mrows:
        lines.append(f"{r['model']},{r['requests']},{r['tokens']},{round(float(r['cost'] or 0), 6)}")
    from quart import Response
    body = '\ufeff' + '\n'.join(lines)  # BOM：Excel 直接打开不乱码
    return Response(body, mimetype='text/csv',
                    headers={'Content-Disposition':
                             f'attachment; filename=usage_export_{days}d.csv'})


# ---------------------------------------------------------------- 公告管理 API

@admin_bp.route('/api/admin/announcements', methods=['GET'])
async def api_admin_announcements_list():
    err = await _require_admin()
    if err:
        return err
    page = request.args.get('page', 1, type=int)
    return jsonify(await _ann.list_announcements(page=page)), 200



@admin_bp.route('/api/admin/announcements', methods=['POST'])
async def api_admin_announcements_create():
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'invalid body'}), 400
    title = (data.get('title') or '').strip()
    content = (data.get('content') or '').strip()
    level = data.get('level', 'info')
    target = data.get('target', 'all')
    target_uids = data.get('target_uids') or []
    pinned = bool(data.get('pinned', False))
    admin_user = await _get_current_user()
    sender_uid = admin_user['uid'] if admin_user else ''
    sender_name = admin_user['user_name'] if admin_user else 'admin'
    try:
        delivered = await _ann.broadcast_announcement(
            title=title, content=content, level=level,
            sender_uid=sender_uid, sender_name=sender_name,
            target=target, target_uids=target_uids, pinned=pinned
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    # 触发钩子事件
    await fire_event('ANNOUNCEMENT_SEND',
                     trigger_user=sender_uid,
                     content=title or content)
    return jsonify({'message': '公告已发布', 'delivered': delivered}), 200



@admin_bp.route('/api/admin/announcements/<announcement_id>', methods=['GET'])
async def api_admin_announcements_detail(announcement_id):
    err = await _require_admin()
    if err:
        return err
    a = await _ann.get_announcement(announcement_id)
    if not a:
        return jsonify({'error': 'not found'}), 404
    return jsonify(a), 200



@admin_bp.route('/api/admin/announcements/<announcement_id>', methods=['DELETE'])
async def api_admin_announcements_delete(announcement_id):
    err = await _require_admin()
    if err:
        return err
    purge = request.args.get('purge', '1') != '0'
    ok = await _ann.delete_announcement(announcement_id, purge_messages=purge)
    if not ok:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'message': '公告已撤回'}), 200



@admin_bp.route('/admin/announcements', methods=['GET'])
async def admin_announcements_page():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_announcements.html')


# ---------------------------------------------------------------- 钩子管理 API

@admin_bp.route('/api/admin/hooks/meta', methods=['GET'])
async def api_admin_hooks_meta():
    err = await _require_admin()
    if err:
        return err
    return jsonify(_hooks.hook_meta()), 200



@admin_bp.route('/api/admin/hooks', methods=['GET'])
async def api_admin_hooks_list():
    err = await _require_admin()
    if err:
        return err
    return jsonify({'hooks': await _hooks.list_hooks()}), 200



@admin_bp.route('/api/admin/hooks', methods=['POST'])
async def api_admin_hooks_create():
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'invalid body'}), 400
    try:
        res = await _hooks.create_hook(
            name=data.get('name', '未命名钩子'),
            events=data.get('events', ''),
            condition=data.get('condition', '') or '',
            actions=data.get('actions', ''),
            description=data.get('description', '') or '',
            priority=int(data.get('priority', 100)),
            is_enabled=bool(data.get('is_enabled', True)),
            created_by=session.get('user', 'admin')
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    return jsonify(res), 201



@admin_bp.route('/api/admin/hooks/<hook_id>', methods=['GET'])
async def api_admin_hooks_get(hook_id):
    err = await _require_admin()
    if err:
        return err
    h = await _hooks.get_hook(hook_id)
    if not h:
        return jsonify({'error': 'not found'}), 404
    return jsonify(h), 200



@admin_bp.route('/api/admin/hooks/<hook_id>', methods=['PUT'])
async def api_admin_hooks_update(hook_id):
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'invalid body'}), 400
    try:
        res = await _hooks.update_hook(hook_id, **data)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    return jsonify(res), 200



@admin_bp.route('/api/admin/hooks/<hook_id>', methods=['DELETE'])
async def api_admin_hooks_delete(hook_id):
    err = await _require_admin()
    if err:
        return err
    ok = await _hooks.delete_hook(hook_id)
    if not ok:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'message': 'deleted'}), 200



@admin_bp.route('/api/admin/hooks/test', methods=['POST'])
async def api_admin_hooks_test():
    err = await _require_admin()
    if err:
        return err
    data = await request.get_json() or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'invalid body'}), 400
    out = await _hooks.test_hook(
        events=data.get('events', ''),
        condition=data.get('condition', '') or '',
        actions=data.get('actions', ''),
        trigger_uid=data.get('trigger_uid', '') or '',
        target_uid=data.get('target_uid', '') or '',
        dry_run=bool(data.get('dry_run', True))
    )
    return jsonify(out), 200



@admin_bp.route('/api/admin/hooks/logs', methods=['GET'])
async def api_admin_hooks_logs():
    err = await _require_admin()
    if err:
        return err
    hook_id = request.args.get('hook_id', '')
    limit = request.args.get('limit', 100, type=int)
    return jsonify({'logs': await _hooks.list_hook_logs(hook_id=hook_id, limit=limit)}), 200



@admin_bp.route('/admin/hooks', methods=['GET'])
async def admin_hooks_page():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_hooks.html')


# ---------- 运维设置（余额预警 / 数据备份，DB 持久化 + 热生效）----------

@admin_bp.route('/api/admin/ops-settings', methods=['GET'])
async def api_admin_ops_settings_get():
    err = await _require_admin()
    if err:
        return err
    from .. import ops_settings
    ov = ops_settings.get_overrides()
    smtp = dict(configs.SMTP_SETTINGS or {})
    smtp['pass'] = '******' if smtp.get('pass') else ''
    napcat = dict(getattr(configs, 'NAPCAT', {}) or {})
    napcat['token'] = '******' if napcat.get('token') else ''
    return jsonify({
        'balance_alert': configs.BALANCE_ALERT,
        'db_backup': configs.DB_BACKUP,
        'retention': getattr(configs, 'RETENTION', {}),
        'upstream_health': configs.UPSTREAM_HEALTH,
        'param_limits': configs.PARAM_LIMITS,
        'smtp': smtp,
        'napcat': napcat,
        'token_billing': getattr(configs, 'TOKEN_BILLING', {}),
        'smtp_configured': configs.smtp_configured(),
        'db_type': getattr(configs, 'DB_TYPE', 'sqlite'),
        'overridden': {k: bool(ov.get(k)) for k in
                       ('balance_alert', 'db_backup', 'retention', 'upstream_health',
                        'param_limits', 'smtp', 'napcat', 'token_billing')},
    }), 200


@admin_bp.route('/api/admin/ops-settings', methods=['PUT'])
async def api_admin_ops_settings_put():
    err = await _require_admin()
    if err:
        return err
    from .. import ops_settings
    data = await request.get_json() or {}
    section = (data.get('section') or '').strip()
    values = data.get('values')
    if not isinstance(values, dict):
        return jsonify({'error': 'values must be an object'}), 400
    ok, error = await asyncio.to_thread(ops_settings.save, section, values)
    if not ok:
        return jsonify({'error': error}), 400
    return jsonify({'ok': True,
                    section: getattr(configs, section.upper(), {})}), 200


@admin_bp.route('/api/admin/ops-settings/backup-now', methods=['POST'])
async def api_admin_ops_backup_now():
    """手动立即备份一次（复用定时备份同一条 pg_dump 链路）。"""
    err = await _require_admin()
    if err:
        return err
    from .. import pg_backup
    try:
        path = await asyncio.to_thread(pg_backup.run_backup)
        return jsonify({'ok': True, 'file': os.path.basename(path)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/ops-settings/notify-test', methods=['POST'])
async def api_admin_ops_notify_test():
    """向已配置的推送渠道发一条测试消息（当前仅 NapCat）。"""
    err = await _require_admin()
    if err:
        return err
    from .. import notify
    nap = dict(getattr(configs, 'NAPCAT', {}) or {})
    if not nap.get('enabled'):
        return jsonify({'error': 'NapCat 推送未启用，请先勾选启用并保存'}), 400
    targets = notify._targets(nap, '测试消息', '连通性预检')
    if not targets:
        return jsonify({'error': '没有可用的接收目标：请填写 QQ 号或群号'}), 400
    queued = notify.notify('测试消息',
                           f'NapCat 通道连通性测试 @ {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n'
                           '如果你在 QQ 里看到这条消息，说明推送链路已打通。')
    return jsonify({'ok': True, 'queued': queued}), 200


@admin_bp.route('/admin/settings', methods=['GET'])
async def admin_settings_page():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if not await _is_admin():
        return redirect(url_for('dashboard'))
    return await render_template('admin_settings.html')


import os
DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'docs')


# ---------- 套餐 / 订阅管理 ----------

async def _admin_or_403():
    """管理员守卫：通过返回 None，否则返回 (resp, status)。"""
    username = session.get('user')
    if not username:
        return jsonify({'error': 'unauthorized'}), 401
    if not await _is_admin():
        return jsonify({'error': 'forbidden'}), 403
    return None


@admin_bp.route('/api/admin/plans', methods=['GET'])
async def admin_list_plans():
    guard = await _admin_or_403()
    if guard:
        return guard
    plans = await _subscription.get_plans(only_active=False)
    return jsonify({'plans': plans}), 200


@admin_bp.route('/api/admin/plans', methods=['POST'])
async def admin_create_plan():
    guard = await _admin_or_403()
    if guard:
        return guard
    data = await request.get_json() or {}
    pid = (data.get('id') or '').strip()
    if not pid or not data.get('name'):
        return jsonify({'error': 'id 与 name 必填'}), 400
    feats = data.get('features')
    if isinstance(feats, list):
        feats = json.dumps(feats, ensure_ascii=False)
    try:
        await async_db_query(
            """INSERT INTO subscription_plans (id, name, description, price, period_days, features, active, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)""",
            (pid, data.get('name'), data.get('description', ''),
             float(data.get('price', 0)), int(data.get('period_days', 30)),
             feats or '[]', 1 if data.get('active', True) else 0))
    except Exception as e:
        return jsonify({'error': f'创建失败（id 可能已存在）：{e}'}), 400
    return jsonify({'plan': await _subscription.get_plan(pid)}), 201


@admin_bp.route('/api/admin/plans/<plan_id>', methods=['PUT'])
async def admin_update_plan(plan_id: str):
    guard = await _admin_or_403()
    if guard:
        return guard
    data = await request.get_json() or {}
    fields, params = [], []
    for key in ('name', 'description', 'price', 'period_days', 'active'):
        if key in data and data[key] is not None:
            fields.append(f"{key} = ?")
            params.append(data[key] if key not in ('price', 'period_days')
                          else (float(data[key]) if key == 'price' else int(data[key])))
    if 'active' in data:
        # 上面已处理为 0/1，确保类型
        fields[-1] = "active = ?"
        params[-1] = 1 if data['active'] else 0
    feats = data.get('features')
    if feats is not None:
        fields.append("features = ?")
        params.append(json.dumps(feats, ensure_ascii=False) if isinstance(feats, list) else str(feats))
    if not fields:
        return jsonify({'plan': await _subscription.get_plan(plan_id)}), 200
    params.append(plan_id)
    await async_db_query(
        f"UPDATE subscription_plans SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        params)
    return jsonify({'plan': await _subscription.get_plan(plan_id)}), 200


@admin_bp.route('/api/admin/plans/<plan_id>', methods=['DELETE'])
async def admin_delete_plan(plan_id: str):
    guard = await _admin_or_403()
    if guard:
        return guard
    # 软删除：下架而非物理删除，避免已订阅用户产生孤儿记录
    await async_db_query("UPDATE subscription_plans SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (plan_id,))
    return jsonify({'ok': True}), 200




