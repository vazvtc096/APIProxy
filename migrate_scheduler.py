"""
定时任务系统数据库迁移脚本
添加 scheduled_tasks 和 task_execution_logs 表
"""
import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'users.db')

def column_exists(cur, table, column):
    """检查列是否存在"""
    cur.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cur.fetchall()]
    return column in columns

def migrate_scheduler():
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    print("正在迁移定时任务数据库...")
    
    # 1. scheduled_tasks 表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT NOT NULL,
            behavior TEXT NOT NULL,
            scope TEXT NOT NULL,
            params TEXT DEFAULT '{}',
            start_time TIMESTAMP NOT NULL,
            end_time TIMESTAMP,
            frequency TEXT NOT NULL,
            cron_expression TEXT,
            last_run_at TIMESTAMP,
            next_run_at TIMESTAMP,
            is_enabled INTEGER DEFAULT 1,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            run_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active'
        )
    """)
    print("  [OK] scheduled_tasks 表")
    
    # 创建索引
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_enabled ON scheduled_tasks(is_enabled)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_next_run ON scheduled_tasks(next_run_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON scheduled_tasks(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_behavior ON scheduled_tasks(behavior)")
    
    # 2. task_execution_logs 表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS task_execution_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            result TEXT NOT NULL,
            output TEXT,
            duration_ms INTEGER
        )
    """)
    print("  [OK] task_execution_logs 表")
    
    # 创建索引
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_task_id ON task_execution_logs(task_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_executed_at ON task_execution_logs(executed_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_result ON task_execution_logs(result)")
    
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 40)
    print("定时任务数据库迁移完成！")
    print("=" * 40)

if __name__ == '__main__':
    migrate_scheduler()
