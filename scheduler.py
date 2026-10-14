"""
定时任务调度器模块
支持多种任务类型和频率，使用后台线程轮询执行
"""
import asyncio
import sqlite3
import json
import datetime
import threading
import time
import logging
from typing import Optional, Dict, Any, List

# 从配置模块导入数据库路径
try:
    from .configs import DB_PATH
except ImportError:
    DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

logger = logging.getLogger(__name__)

# ---------- 数据库辅助函数 ----------
def _get_conn():
    """获取数据库连接（SQLite / PostgreSQL，经 db 抽象层统一）"""
    from . import db
    return db.get_conn()

def _db_query(sql, args=None):
    """执行数据库查询（同步）"""
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(sql, args or ())
            if sql.strip().upper().startswith("SELECT"):
                rows = cur.fetchall()
                return [dict(row) for row in rows]
            else:
                conn.commit()
                return cur.rowcount
    finally:
        conn.close()

def _db_transaction(operations):
    """执行数据库事务（同步）"""
    conn = _get_conn()
    try:
        db.begin_write(conn)
        cur = conn.cursor()
        results = []
        for sql, args in operations:
            cur.execute(sql, args or ())
            if sql.strip().upper().startswith("SELECT"):
                results.append([dict(row) for row in cur.fetchall()])
            else:
                results.append(cur.rowcount)
        conn.commit()
        return results
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

# ---------- 频率计算函数 ----------
def calculate_next_run(frequency: str, current_time: datetime.datetime, cron_expression: str = None) -> Optional[datetime.datetime]:
    """计算下次执行时间"""
    if frequency == 'once':
        return None  # 一次性任务执行后不再执行
    
    if frequency == 'minute':
        return current_time + datetime.timedelta(minutes=1)
    
    if frequency == 'hourly':
        return current_time + datetime.timedelta(hours=1)
    
    if frequency == 'daily':
        return current_time + datetime.timedelta(days=1)
    
    if frequency == 'weekly':
        return current_time + datetime.timedelta(weeks=1)
    
    if frequency == 'monthly':
        # 简单处理：加30天
        return current_time + datetime.timedelta(days=30)
    
    # cron 表达式（简化处理，只支持部分格式）
    if frequency == 'cron' and cron_expression:
        # 这里简化处理，实际应该用 cron 解析库
        return current_time + datetime.timedelta(minutes=1)
    
    return None

# ---------- 任务执行器 ----------
class TaskExecutor:
    """任务执行器 - 执行各种类型的任务"""
    
    @staticmethod
    def execute_task(task: dict) -> tuple:
        """
        执行任务
        Returns: (success: bool, output: str)
        """
        try:
            behavior = task['behavior']
            scope = task['scope']
            params = json.loads(task.get('params', '{}'))
            
            if behavior == 'user_balence_add':
                return TaskExecutor._user_balence_add(scope, params)
            elif behavior == 'user_balence_subtract':
                return TaskExecutor._user_balence_subtract(scope, params)
            elif behavior == 'user_ban':
                return TaskExecutor._user_ban(scope, params)
            elif behavior == 'user_unban':
                return TaskExecutor._user_unban(scope, params)
            elif behavior == 'post_approve':
                return TaskExecutor._post_approve(scope, params)
            elif behavior == 'post_reject':
                return TaskExecutor._post_reject(scope, params)
            elif behavior == 'system_notice':
                return TaskExecutor._system_notice(scope, params)
            elif behavior == 'custom_command':
                return TaskExecutor._custom_command(scope, params)
            elif behavior == 'dsl':
                return TaskExecutor._dsl_execute(scope, params)
            else:
                return False, f"未知行为类型: {behavior}"
                
        except Exception as e:
            logger.error(f"任务执行异常: {e}")
            return False, f"执行异常: {str(e)}"
    
    @staticmethod
    def _user_balence_add(scope: str, params: dict) -> tuple:
        """给用户增加余额"""
        amount = float(params.get('amount', 0))
        if amount <= 0:
            return False, "金额必须为正数"
        
        affected = 0
        
        if scope == 'all_users':
            # 给所有用户增加余额
            result = _db_query(
                "UPDATE users SET balence = balence + ?",
                (amount,)
            )
            affected = result if isinstance(result, int) else 0
            
        elif scope == 'specific_user':
            # 给指定用户增加余额
            uid = params.get('uid')
            if not uid:
                return False, "缺少用户UID"
            result = _db_query(
                "UPDATE users SET balence = balence + ? WHERE uid = ?",
                (amount, uid)
            )
            affected = result if isinstance(result, int) else 0
            
        elif scope == 'user_group':
            # 按条件筛选用户
            min_balence = params.get('min_balence')
            max_balence = params.get('max_balence')
            
            sql = "UPDATE users SET balence = balence + ? WHERE 1=1"
            args = [amount]
            
            if min_balence is not None:
                sql += " AND balence >= ?"
                args.append(float(min_balence))
            if max_balence is not None:
                sql += " AND balence <= ?"
                args.append(float(max_balence))
            
            result = _db_query(sql, args)
            affected = result if isinstance(result, int) else 0
        
        # 记录交易
        try:
            _db_query(
                """INSERT INTO balence_transactions 
                   (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
                   VALUES (?, 'system', 'system', 'scheduled', ?, 0, ?, ?)""",
                (f'tx_sched_{int(time.time())}', amount, scope, f'定时任务批量增加余额，影响 {affected} 人')
            )
        except:
            pass
        
        return True, f"成功给 {affected} 个用户增加了 {amount} 元余额"
    
    @staticmethod
    def _user_balence_subtract(scope: str, params: dict) -> tuple:
        """给用户扣除余额"""
        amount = float(params.get('amount', 0))
        if amount <= 0:
            return False, "金额必须为正数"
        
        affected = 0
        
        if scope == 'all_users':
            result = _db_query(
                "UPDATE users SET balence = balence - ? WHERE balence >= ?",
                (amount, amount)
            )
            affected = result if isinstance(result, int) else 0
            
        elif scope == 'specific_user':
            uid = params.get('uid')
            if not uid:
                return False, "缺少用户UID"
            result = _db_query(
                "UPDATE users SET balence = balence - ? WHERE uid = ? AND balence >= ?",
                (amount, uid, amount)
            )
            affected = result if isinstance(result, int) else 0
        
        return True, f"成功给 {affected} 个用户扣除了 {amount} 元余额"
    
    @staticmethod
    def _user_ban(scope: str, params: dict) -> tuple:
        """封禁用户"""
        reason = params.get('reason', '定时任务封禁')
        days = params.get('days')
        expire_at = None
        if days:
            expire_at = (datetime.datetime.now() + datetime.timedelta(days=int(days))).strftime('%Y-%m-%d %H:%M:%S')

        affected = 0
        if scope == 'all_users':
            result = _db_query(
                "UPDATE users SET is_banned = 1, ban_reason = ?, ban_expire_at = ? WHERE is_admin = 0",
                (reason, expire_at)
            )
            affected = result if isinstance(result, int) else 0
        elif scope == 'user_group':
            min_balence = params.get('min_balence')
            max_balence = params.get('max_balence')
            sql = "UPDATE users SET is_banned = 1, ban_reason = ?, ban_expire_at = ? WHERE is_admin = 0"
            args: list = [reason, expire_at]
            if min_balence is not None:
                sql += " AND balence >= ?"
                args.append(float(min_balence))
            if max_balence is not None:
                sql += " AND balence <= ?"
                args.append(float(max_balence))
            result = _db_query(sql, args)
            affected = result if isinstance(result, int) else 0
        elif scope == 'specific_user':
            uid = params.get('uid')
            if not uid:
                return False, "缺少用户UID"
            result = _db_query(
                "UPDATE users SET is_banned = 1, ban_reason = ?, ban_expire_at = ? WHERE uid = ? AND is_admin = 0",
                (reason, expire_at, uid)
            )
            affected = result if isinstance(result, int) else 0
        else:
            return False, f"不支持的封禁范围: {scope}"

        return True, f"成功封禁 {affected} 个用户"
    
    @staticmethod
    def _user_unban(scope: str, params: dict) -> tuple:
        """解禁用户"""
        affected = 0
        
        if scope == 'specific_user':
            uid = params.get('uid')
            if not uid:
                return False, "缺少用户UID"
            
            result = _db_query(
                "UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expire_at = NULL WHERE uid = ?",
                (uid,)
            )
            affected = result if isinstance(result, int) else 0
        
        return True, f"成功解禁 {affected} 个用户"
    
    @staticmethod
    def _post_approve(scope: str, params: dict) -> tuple:
        """审核通过帖子"""
        affected = 0
        
        if scope == 'all_posts':
            # 审核所有待审核帖子
            result = _db_query(
                """UPDATE posts SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP, reviewed_by = 'scheduled'
                   WHERE status = 'pending'""",
            )
            affected = result if isinstance(result, int) else 0
            
        elif scope == 'specific_post':
            post_id = params.get('post_id')
            if not post_id:
                return False, "缺少帖子ID"
            
            result = _db_query(
                """UPDATE posts SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP, reviewed_by = 'scheduled'
                   WHERE post_id = ? AND status = 'pending'""",
                (post_id,)
            )
            affected = result if isinstance(result, int) else 0
        
        return True, f"成功审核通过 {affected} 个帖子"
    
    @staticmethod
    def _post_reject(scope: str, params: dict) -> tuple:
        """拒绝帖子"""
        reason = params.get('reason', '定时任务拒绝')
        affected = 0
        
        if scope == 'all_posts':
            result = _db_query(
                """UPDATE posts SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP, reviewed_by = 'scheduled', admin_remark = ?
                   WHERE status = 'pending'""",
                (reason,)
            )
            affected = result if isinstance(result, int) else 0
            
        elif scope == 'specific_post':
            post_id = params.get('post_id')
            if not post_id:
                return False, "缺少帖子ID"
            
            result = _db_query(
                """UPDATE posts SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP, reviewed_by = 'scheduled', admin_remark = ?
                   WHERE post_id = ? AND status = 'pending'""",
                (reason, post_id)
            )
            affected = result if isinstance(result, int) else 0
        
        return True, f"成功拒绝 {affected} 个帖子"
    
    @staticmethod
    def _system_notice(scope: str, params: dict) -> tuple:
        """发送系统公告"""
        content = params.get('content', '')
        if not content:
            return False, "缺少公告内容"
        
        # 简单实现：记录到系统配置或发送给所有用户
        # 这里我们记录到 balence_transactions 作为系统通知
        affected = 0
        
        if scope == 'all_users':
            # 给所有用户发送系统消息（发件人为系统虚拟用户 0x0「系统」，可进入聊天）
            try:
                from .system_users import system_sender
                sys_uid, sys_name = system_sender('000000000000')
            except Exception:
                sys_uid, sys_name = '000000000000', '系统'
            users = [u for u in _db_query("SELECT uid, user_name FROM users")
                     if u.get('uid') and u['uid'] != sys_uid]
            for user in users:
                try:
                    _db_query(
                        """INSERT INTO chat_messages (message_id, from_uid, from_name, to_uid, to_name, content, type, status)
                           VALUES (?, ?, ?, ?, ?, ?, 'system', 'sent')""",
                        (f'msg_sys_{int(time.time())}_{user["uid"]}', sys_uid, sys_name, user['uid'], user['user_name'], content)
                    )
                    affected += 1
                except:
                    pass
        
        return True, f"成功发送系统公告给 {affected} 个用户"
    
    @staticmethod
    def _custom_command(scope: str, params: dict) -> tuple:
        """执行自定义命令"""
        command = params.get('command', '')
        if not command:
            return False, "缺少命令"
        
        # 安全限制：只允许特定命令
        allowed_commands = ['list_users', 'stats', 'status']
        if command not in allowed_commands:
            return False, f"不允许执行的命令: {command}"
        
        # 这里可以调用 Debug Console 命令执行
        try:
            # 简化处理：只记录日志
            logger.info(f"执行自定义命令: {command}")
            return True, f"命令 {command} 执行成功"
        except Exception as e:
            return False, f"命令执行失败: {str(e)}"

    @staticmethod
    def _dsl_execute(scope: str, params: dict) -> tuple:
        """执行 DSL 动作（复用 hooks 引擎的条件求值 + 动作执行）。

        params 字段：
          - condition: 条件表达式（留空 = 恒真），与 hooks 同语法
          - actions:   动作串（; 分隔多个），如 send_announcement("提醒", "内容")
          - trigger_uid: 可选，指定触发用户（用于 TRIGGER_USER 上下文）
          - 其余字段注入上下文 extra
        """
        try:
            from . import hooks
        except ImportError:
            return False, "无法加载 DSL 引擎"

        condition = params.get('condition', '')
        actions = params.get('actions', '')
        if not actions:
            return False, "DSL 动作为空"

        async def _run():
            ctx = await hooks.build_context('SCHEDULED_TASK', {
                'trigger_user': params.get('trigger_uid') or None,
                'content': params.get('content', ''),
                'reason': params.get('reason', ''),
                'extra': {
                    k: v for k, v in params.items()
                    if k not in ('condition', 'actions', 'trigger_uid', 'content', 'reason')
                },
            })
            # 条件求值
            if (condition or '').strip():
                if not hooks.evaluate_condition(condition, ctx):
                    return True, "条件不满足，跳过执行"
            # 执行动作
            results = await hooks.run_actions(actions, ctx)
            return True, "; ".join(results) if results else "无动作执行"

        try:
            loop = asyncio.new_event_loop()
            try:
                success, output = loop.run_until_complete(_run())
            finally:
                loop.close()
            return success, output
        except Exception as e:
            logger.error(f"DSL 任务执行异常: {e}")
            return False, f"DSL 执行异常: {e}"

# ---------- 调度器 ----------
class TaskScheduler:
    """定时任务调度器"""
    
    def __init__(self):
        self.running = False
        self.thread = None
        self.check_interval = 30  # 每30秒检查一次
    
    def start(self):
        """启动调度器"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True, name='TaskScheduler')
        self.thread.start()
        logger.info("定时任务调度器已启动")
    
    def stop(self):
        """停止调度器"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("定时任务调度器已停止")
    
    def _run(self):
        """调度器主循环"""
        while self.running:
            try:
                self._check_and_run_tasks()
            except Exception as e:
                logger.error(f"调度器检查任务异常: {e}")
            
            # 等待下一次检查
            for _ in range(self.check_interval):
                if not self.running:
                    break
                time.sleep(1)
    
    def _check_and_run_tasks(self):
        """检查并执行到期的任务（原子抢占，防止多实例/多线程重复执行）。

        做法：在统一事务内先 SELECT 候选、再带条件 UPDATE 抢占为 'running'
        （SQLite 由进程内写锁串行化；PostgreSQL 由事务内 UPDATE 条件保证
        只有一个实例抢到）。抢占失败则本轮无任务。长时间停留在 running 的
        任务（上次执行异常未复位）会被超时回收为 active。
        """
        now = datetime.datetime.now()
        now_str = now.strftime('%Y-%m-%d %H:%M:%S')
        reclaim_cut = (now - datetime.timedelta(seconds=600)).strftime('%Y-%m-%d %H:%M:%S')

        from . import db
        task = None
        with db.transaction() as conn:
            cur = conn.cursor()
            if db.is_postgres():
                # PostgreSQL：SELECT ... FOR UPDATE SKIP LOCKED —— 真正的分布式互斥。
                # 多个 Worker 并发抢同一批候选时，已加锁的行会被跳过，保证同一时刻
                # 只有一个实例能拿到并抢占该任务；无需依赖进程内锁。
                cur.execute(
                    """SELECT * FROM scheduled_tasks
                       WHERE is_enabled = 1 AND (
                           (status = 'active' AND next_run_at <= %s)
                           OR (status = 'running' AND last_run_at <= %s)
                       )
                       ORDER BY next_run_at ASC
                       FOR UPDATE SKIP LOCKED
                       LIMIT 1""",
                    (now_str, reclaim_cut),
                )
                row = cur.fetchone()
                if not row:
                    return
                cur.execute(
                    "UPDATE scheduled_tasks SET status = 'running', last_run_at = %s "
                    "WHERE id = %s AND status IN ('active', 'running') "
                    "RETURNING *",
                    (now_str, row['id']),
                )
            else:
                # SQLite：先取候选，再带条件抢占（事务内串行，自带原子性）
                cur.execute(
                    """SELECT * FROM scheduled_tasks
                       WHERE is_enabled = 1 AND (
                           (status = 'active' AND next_run_at <= ?)
                           OR (status = 'running' AND last_run_at <= ?)
                       )
                       ORDER BY next_run_at ASC LIMIT 1""",
                    (now_str, reclaim_cut),
                )
                row = cur.fetchone()
                if not row:
                    return
                cur.execute(
                    "UPDATE scheduled_tasks SET status = 'running', last_run_at = ? "
                    "WHERE id = ? AND status IN ('active', 'running') "
                    "RETURNING *",
                    (now_str, row['id']),
                )
            r = cur.fetchone()
            if r:
                task = dict(r)

        if task:
            self._execute_single_task(task, now)
    
    def _execute_single_task(self, task: dict, now: datetime.datetime):
        """执行单个任务"""
        task_id = task['id']
        start_time = time.time()
        
        try:
            # 执行任务
            success, output = TaskExecutor.execute_task(task)
            
            # 计算执行耗时
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 记录执行日志
            _db_query(
                """INSERT INTO task_execution_logs (task_id, result, output, duration_ms)
                   VALUES (?, ?, ?, ?)""",
                (task_id, 'success' if success else 'failed', output, duration_ms)
            )
            
            # 更新任务状态
            now_str = now.strftime('%Y-%m-%d %H:%M:%S')
            frequency = task['frequency']
            
            if frequency == 'once':
                # 一次性任务执行后标记为完成
                _db_query(
                    """UPDATE scheduled_tasks 
                       SET last_run_at = ?, run_count = run_count + 1, status = 'completed', is_enabled = 0
                       WHERE id = ?""",
                    (now_str, task_id)
                )
            else:
                # 计算下次执行时间
                next_run = calculate_next_run(frequency, now, task.get('cron_expression'))
                
                # 检查是否超过结束时间
                end_time = task.get('end_time')
                if end_time and next_run:
                    end_dt = datetime.datetime.fromisoformat(str(end_time))
                    if next_run > end_dt:
                        # 超过结束时间，标记为完成
                        _db_query(
                            """UPDATE scheduled_tasks 
                               SET last_run_at = ?, run_count = run_count + 1, status = 'completed', is_enabled = 0
                               WHERE id = ?""",
                            (now_str, task_id)
                        )
                        return
                
                next_run_str = next_run.strftime('%Y-%m-%d %H:%M:%S') if next_run else None
                
                _db_query(
                    """UPDATE scheduled_tasks 
                       SET last_run_at = ?, next_run_at = ?, run_count = run_count + 1
                       WHERE id = ?""",
                    (now_str, next_run_str, task_id)
                )
            
            logger.info(f"任务 {task_id} ({task['task_name']}) 执行完成: {'成功' if success else '失败'} - {output}")
            
        except Exception as e:
            logger.error(f"任务 {task_id} 执行异常: {e}")
            # 记录失败日志
            try:
                duration_ms = int((time.time() - start_time) * 1000)
                _db_query(
                    """INSERT INTO task_execution_logs (task_id, result, output, duration_ms)
                       VALUES (?, 'failed', ?, ?)""",
                    (task_id, str(e), duration_ms)
                )
            except:
                pass

# ---------- 任务管理函数 ----------
def create_task(task_name: str, behavior: str, scope: str, params: dict,
                start_time: str, frequency: str, end_time: str = None,
                cron_expression: str = None, created_by: str = None) -> int:
    """创建定时任务"""
    
    # 验证参数
    valid_behaviors = ['user_balence_add', 'user_balence_subtract', 'user_ban', 
                       'user_unban', 'post_approve', 'post_reject', 
                       'system_notice', 'custom_command', 'dsl']
    if behavior not in valid_behaviors:
        raise ValueError(f"无效的行为类型: {behavior}")
    
    valid_scopes = ['all_users', 'specific_user', 'user_group', 'all_posts', 'specific_post', 'none']
    if scope not in valid_scopes:
        raise ValueError(f"无效的影响范围: {scope}")
    
    valid_frequencies = ['once', 'minute', 'hourly', 'daily', 'weekly', 'monthly', 'cron']
    if frequency not in valid_frequencies:
        raise ValueError(f"无效的频率: {frequency}")
    
    # 计算下次执行时间
    start_dt = datetime.datetime.fromisoformat(start_time)
    now = datetime.datetime.now()
    
    if start_dt <= now:
        # 如果开始时间已过，从现在开始计算
        next_run = calculate_next_run(frequency, now, cron_expression)
    else:
        next_run = start_dt
    
    next_run_str = next_run.strftime('%Y-%m-%d %H:%M:%S') if next_run else None
    
    # 插入任务
    params_json = json.dumps(params, ensure_ascii=False)
    
    result = _db_query(
        """INSERT INTO scheduled_tasks 
           (task_name, behavior, scope, params, start_time, end_time, frequency, 
            cron_expression, next_run_at, created_by, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')""",
        (task_name, behavior, scope, params_json, start_time, end_time, 
         frequency, cron_expression, next_run_str, created_by)
    )
    
    # 获取新创建的任务ID
    tasks = _db_query("SELECT last_insert_rowid() as id")
    task_id = tasks[0]['id'] if tasks else 0
    
    logger.info(f"创建定时任务: {task_id} - {task_name}")
    return task_id

def delete_task(task_id: int) -> bool:
    """删除定时任务"""
    result = _db_query("DELETE FROM scheduled_tasks WHERE id = ?", (task_id,))
    return result > 0 if isinstance(result, int) else False

def pause_task(task_id: int) -> bool:
    """暂停任务"""
    result = _db_query(
        "UPDATE scheduled_tasks SET is_enabled = 0, status = 'paused' WHERE id = ?",
        (task_id,)
    )
    return result > 0 if isinstance(result, int) else False

def resume_task(task_id: int) -> bool:
    """恢复任务"""
    # 重新计算下次执行时间
    tasks = _db_query("SELECT * FROM scheduled_tasks WHERE id = ?", (task_id,))
    if not tasks:
        return False
    
    task = tasks[0]
    now = datetime.datetime.now()
    next_run = calculate_next_run(task['frequency'], now, task.get('cron_expression'))
    next_run_str = next_run.strftime('%Y-%m-%d %H:%M:%S') if next_run else None
    
    result = _db_query(
        "UPDATE scheduled_tasks SET is_enabled = 1, status = 'active', next_run_at = ? WHERE id = ?",
        (next_run_str, task_id)
    )
    return result > 0 if isinstance(result, int) else False

def run_task_now(task_id: int) -> tuple:
    """手动触发执行一次任务"""
    tasks = _db_query("SELECT * FROM scheduled_tasks WHERE id = ?", (task_id,))
    if not tasks:
        return False, "任务不存在"
    
    task = tasks[0]
    success, output = TaskExecutor.execute_task(task)
    
    # 记录执行日志
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    _db_query(
        """INSERT INTO task_execution_logs (task_id, executed_at, result, output, duration_ms)
           VALUES (?, ?, ?, ?, 0)""",
        (task_id, now, 'success' if success else 'failed', output)
    )
    
    # 更新执行次数
    _db_query(
        "UPDATE scheduled_tasks SET run_count = run_count + 1, last_run_at = ? WHERE id = ?",
        (now, task_id)
    )
    
    return success, output

def list_tasks(status: str = None) -> list:
    """获取任务列表"""
    sql = "SELECT * FROM scheduled_tasks"
    args = []
    
    if status and status != 'all':
        sql += " WHERE status = ?"
        args.append(status)
    
    sql += " ORDER BY created_at DESC"
    
    return _db_query(sql, args)

def get_task(task_id: int) -> Optional[dict]:
    """获取任务详情"""
    tasks = _db_query("SELECT * FROM scheduled_tasks WHERE id = ?", (task_id,))
    return tasks[0] if tasks else None

def get_task_logs(task_id: int, limit: int = 50) -> list:
    """获取任务执行日志"""
    return _db_query(
        "SELECT * FROM task_execution_logs WHERE task_id = ? ORDER BY executed_at DESC LIMIT ?",
        (task_id, limit)
    )

# ---------- 全局调度器实例 ----------
_scheduler = None

def get_scheduler() -> TaskScheduler:
    """获取全局调度器实例"""
    global _scheduler
    if _scheduler is None:
        _scheduler = TaskScheduler()
    return _scheduler

def start_scheduler():
    """启动全局调度器"""
    scheduler = get_scheduler()
    if not scheduler.running:
        scheduler.start()

def stop_scheduler():
    """停止全局调度器"""
    global _scheduler
    if _scheduler:
        _scheduler.stop()
        _scheduler = None

# ---------- 注册 API 路由 ----------
def register_scheduler_routes(app):
    """注册定时任务 API 路由"""
    from quart import request, session, jsonify
    
    def _require_admin():
        """检查管理员权限（基于数据库 is_admin 字段，避免越权）"""
        if 'user' not in session:
            return False
        user_name = session.get('user')
        if not user_name:
            return False
        try:
            rows = _db_query("SELECT is_admin FROM users WHERE user_name = ?", (user_name,))
            return bool(rows and rows[0].get('is_admin', 0))
        except Exception:
            return False
    
    @app.route('/api/tasks', methods=['GET'])
    async def api_list_tasks():
        """获取任务列表"""
        if not _require_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        status = request.args.get('status', 'all')
        tasks = list_tasks(status)
        return jsonify({'tasks': tasks, 'total': len(tasks)})
    
    @app.route('/api/tasks', methods=['POST'])
    async def api_create_task():
        """创建任务"""
        if not _require_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        data = await request.get_json()
        
        try:
            task_id = create_task(
                task_name=data.get('task_name', ''),
                behavior=data.get('behavior', ''),
                scope=data.get('scope', ''),
                params=data.get('params', {}),
                start_time=data.get('start_time', ''),
                frequency=data.get('frequency', 'daily'),
                end_time=data.get('end_time'),
                cron_expression=data.get('cron_expression'),
                created_by=session.get('user', '')
            )
            return jsonify({'message': 'Task created successfully', 'task_id': task_id}), 201
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Failed to create task: {str(e)}'}), 500
    
    @app.route('/api/tasks/<int:task_id>', methods=['GET'])
    async def api_get_task(task_id):
        """获取任务详情"""
        if not _require_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        task = get_task(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        return jsonify({'task': task})
    
    @app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
    async def api_delete_task(task_id):
        """删除任务"""
        if not _require_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        success = delete_task(task_id)
        if not success:
            return jsonify({'error': 'Task not found'}), 404
        
        return jsonify({'message': 'Task deleted successfully'})
    
    @app.route('/api/tasks/<int:task_id>/pause', methods=['POST'])
    async def api_pause_task(task_id):
        """暂停任务"""
        if not _require_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        success = pause_task(task_id)
        if not success:
            return jsonify({'error': 'Task not found'}), 404
        
        return jsonify({'message': 'Task paused successfully'})
    
    @app.route('/api/tasks/<int:task_id>/resume', methods=['POST'])
    async def api_resume_task(task_id):
        """恢复任务"""
        if not _require_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        success = resume_task(task_id)
        if not success:
            return jsonify({'error': 'Task not found'}), 404
        
        return jsonify({'message': 'Task resumed successfully'})
    
    @app.route('/api/tasks/<int:task_id>/run', methods=['POST'])
    async def api_run_task(task_id):
        """手动执行任务"""
        if not _require_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        success, output = run_task_now(task_id)
        return jsonify({
            'success': success,
            'output': output
        })
    
    @app.route('/api/tasks/<int:task_id>/logs', methods=['GET'])
    async def api_task_logs(task_id):
        """获取任务执行日志"""
        if not _require_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        
        limit = request.args.get('limit', 50, type=int)
        logs = get_task_logs(task_id, limit)
        return jsonify({'logs': logs, 'total': len(logs)})
