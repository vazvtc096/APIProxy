import sqlite3
import os
import bcrypt
import uuid

db_path = os.path.join(os.path.dirname(__file__), 'users.db')

def init_complete_db():
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    print("正在初始化数据库...")
    
    # 1. users 表（完整结构）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT UNIQUE,
            user_password TEXT,
            apikeys TEXT DEFAULT '',
            balence REAL DEFAULT 0.0,
            uid TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_admin INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            ban_expire_at TIMESTAMP,
            email TEXT UNIQUE,
            last_login_ip TEXT,
            last_login_time TIMESTAMP,
            last_login_user_agent TEXT,
            last_device_type TEXT,
            last_device_os TEXT,
            max_sessions INTEGER DEFAULT 1,
            max_overdraft REAL DEFAULT 0.0,
            allow_overdraft INTEGER DEFAULT 0,
            must_change_password INTEGER DEFAULT 0,
            last_active_time TIMESTAMP,
            login_count INTEGER DEFAULT 0,
            total_spent REAL DEFAULT 0.0
        )
    """)
    print("  [OK] users 表")
    
    # 2. recharge_requests 表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS recharge_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE,
            user_uid TEXT,
            user_name TEXT,
            amount REAL,
            status TEXT DEFAULT 'pending',
            admin_uid TEXT,
            admin_name TEXT,
            admin_remark TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed_at TIMESTAMP
        )
    """)
    print("  [OK] recharge_requests 表")
    
    # 4. login_logs 表（登录日志）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT,
            user_name TEXT,
            login_ip TEXT,
            user_agent TEXT,
            status TEXT,  -- success, failed
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] login_logs 表")
    
    # 5. sessions 表（活跃会话）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            user_name TEXT,
            user_uid TEXT,
            user_agent TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_active_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        )
    """)
    print("  [OK] sessions 表")
    
    # 6. system_config 表（系统配置）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] system_config 表")
    

    # 7. rcon_config 表（RCON 配置）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rcon_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            rcon_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_refreshed_at TIMESTAMP
        )
    """)
    print("  [OK] rcon_config 表")

    # 7.1 rcon_keys 表（RCON 多密钥管理）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rcon_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL UNIQUE,
            key_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            last_used_ip TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_rcon_keys_hash_active "
                "ON rcon_keys(key_hash, is_active)")
    print("  [OK] rcon_keys 表")

    # 7. posts 表（社区帖子）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id TEXT UNIQUE,
            user_uid TEXT,
            user_name TEXT,
            title TEXT,
            content TEXT,
            status TEXT DEFAULT 'pending',  -- pending, approved, rejected
            likes INTEGER DEFAULT 0,
            admin_remark TEXT,
            approved_by TEXT,
            approved_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] posts 表")

    # 7.2 OAuth 2.0 相关表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS oauth_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT UNIQUE,
            client_secret_hash TEXT,
            client_name TEXT,
            owner_name TEXT,
            redirect_uris TEXT,
            grant_types TEXT,
            scopes TEXT,
            is_confidential INTEGER DEFAULT 1,
            token_endpoint_auth_method TEXT DEFAULT 'client_secret_basic',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS oauth_auth_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            client_id TEXT,
            user_uid TEXT,
            user_name TEXT,
            scope TEXT,
            redirect_uri TEXT,
            code_challenge TEXT,
            code_challenge_method TEXT,
            expires_at REAL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_jti TEXT UNIQUE,
            refresh_token TEXT UNIQUE,
            client_id TEXT,
            user_uid TEXT,
            user_name TEXT,
            scope TEXT,
            access_expires_at REAL,
            refresh_expires_at REAL,
            revoked INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS oauth_device_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_code TEXT UNIQUE,
            user_code TEXT UNIQUE,
            client_id TEXT,
            scope TEXT,
            expires_at REAL,
            interval INTEGER DEFAULT 5,
            user_uid TEXT,
            user_name TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] OAuth 表")

    # 7.1 post_favorites 表（帖子收藏）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS post_favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT,
            post_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_uid, post_id)
        )
    """)
    print("  [OK] post_favorites 表")
    
    # 8. friends 表（好友关系）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT,
            friend_uid TEXT,
            friend_name TEXT,
            status TEXT DEFAULT 'pending',  -- pending, accepted, rejected, blocked
            remark TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            accepted_at TIMESTAMP,
            is_protected INTEGER DEFAULT 0  -- 1 = 内置好友（如 admin），不允许删除
        )
    """)
    print("  [OK] friends 表")
    
    # 9. chat_messages 表（聊天消息）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT UNIQUE,
            from_uid TEXT,
            from_name TEXT,
            to_uid TEXT,
            to_name TEXT,
            content TEXT,
            type TEXT DEFAULT 'text',  -- text, redpacket, transfer, system, announcement, recalled
            amount REAL DEFAULT 0.0,
            status TEXT DEFAULT 'sent',  -- sent, read, claimed, expired
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_at TIMESTAMP,
            claimed_at TIMESTAMP,
            is_read INTEGER DEFAULT 0,
            announcement_id TEXT
        )
    """)
    print("  [OK] chat_messages 表")

    # 9.1 post_collections 表（帖子收藏，social.py 口径）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS post_collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT,
            post_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(uid, post_id)
        )
    """)
    print("  [OK] post_collections 表")

    # 9.2 announcements 表（管理员公告）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            announcement_id TEXT UNIQUE,
            title TEXT,
            content TEXT,
            level TEXT DEFAULT 'info',  -- info, warning, critical
            target TEXT DEFAULT 'all',  -- all, users, admins
            target_detail TEXT DEFAULT '',
            sender_uid TEXT,
            sender_name TEXT,
            recipients INTEGER DEFAULT 0,
            pinned INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] announcements 表")

    # 9.3 hooks 表（事件钩子 DSL）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS hooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hook_id TEXT UNIQUE,
            name TEXT,
            description TEXT DEFAULT '',
            events TEXT NOT NULL,       -- 逗号分隔的事件名
            condition TEXT DEFAULT '',  -- DSL 条件表达式
            actions TEXT NOT NULL,      -- DSL 动作，; 分隔
            is_enabled INTEGER DEFAULT 1,
            priority INTEGER DEFAULT 100,
            run_count INTEGER DEFAULT 0,
            match_count INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0,
            last_run_at TIMESTAMP,
            last_error TEXT DEFAULT '',
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] hooks 表")

    # 9.4 hook_logs 表（钩子执行日志）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS hook_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hook_id TEXT,
            hook_name TEXT,
            event_name TEXT,
            trigger_uid TEXT,
            trigger_name TEXT,
            matched INTEGER DEFAULT 0,
            condition_text TEXT DEFAULT '',
            result TEXT DEFAULT '',
            error TEXT DEFAULT '',
            duration_ms INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] hook_logs 表")

    # 9.5 usage_logs 表（API 用量与费用明细）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id TEXT UNIQUE,
            user_uid TEXT,
            user_name TEXT,
            apikey_hash TEXT DEFAULT '',
            model TEXT,
            endpoint TEXT DEFAULT '',
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            total_tokens INTEGER DEFAULT 0,
            cost REAL DEFAULT 0.0,
            is_stream INTEGER DEFAULT 0,
            status TEXT DEFAULT 'success',
            upstream TEXT DEFAULT '',
            duration_ms INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] usage_logs 表")
    
    # 10. balence_transactions 表（余额变动记录）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS balence_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE,
            user_uid TEXT,
            user_name TEXT,
            type TEXT,  -- recharge, chat, transfer_out, transfer_in, redpacket_send, redpacket_recv, admin_adjust
            amount REAL,  -- 正为增加，负为减少
            balence_after REAL,
            related_id TEXT,
            remark TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("  [OK] balence_transactions 表")
    
    # 11. scheduled_tasks 表（定时任务）
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
    
    # 12. task_execution_logs 表（任务执行日志）
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
    
    # 12.5 security_events 表（安全事件审计）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT,
            user_name TEXT,
            event_type TEXT,
            severity TEXT,
            risk_score INTEGER,
            details TEXT,
            client_ip TEXT,
            device_info TEXT,
            action_taken TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 12.6 ip_blacklist 表（IP 封禁名单）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            reason TEXT,
            ban_expire_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 12.7 ip_whitelist 表（IP 白名单：仅 RCON 可控制，白名单 IP 不受拦截）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            note TEXT DEFAULT '',
            bypass TEXT DEFAULT 'all',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 12.8 device_ban 表（设备指纹封禁，由 R3 批量请求规则写入）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_ban (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT UNIQUE,
            reason TEXT,
            ban_expire_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 12.9 config_kv 表（通用键值配置，持久化可自定义封禁规则等）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS config_kv (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # 13. 创建索引
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_uid ON users(uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_recharge_user ON recharge_requests(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_recharge_status ON recharge_requests(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_login_user ON login_logs(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_login_time ON login_logs(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_name)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_post_favorites_user ON post_favorites(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_post_favorites_post ON post_favorites(post_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_friend ON friends(friend_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_status ON friends(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_from ON chat_messages(from_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_to ON chat_messages(to_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_created ON chat_messages(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_unread ON chat_messages(to_uid, is_read)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_ann ON chat_messages(announcement_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ann_created ON announcements(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hooks_enabled ON hooks(is_enabled)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hooks_hook_id ON hooks(hook_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hooklogs_hook ON hook_logs(hook_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hooklogs_created ON hook_logs(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hooklogs_event ON hook_logs(event_name)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_logs(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_logs(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_model ON usage_logs(model)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_user_created ON usage_logs(user_uid, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_postcoll_uid ON post_collections(uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_protected ON friends(is_protected)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_user ON balence_transactions(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_created ON balence_transactions(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_enabled ON scheduled_tasks(is_enabled)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_next_run ON scheduled_tasks(next_run_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON scheduled_tasks(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_behavior ON scheduled_tasks(behavior)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_task_id ON task_execution_logs(task_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_executed_at ON task_execution_logs(executed_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_result ON task_execution_logs(result)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_user ON security_events(user_uid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_created ON security_events(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_severity ON security_events(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ipblack_ip ON ip_blacklist(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ipblack_expire ON ip_blacklist(ban_expire_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ipwhite_ip ON ip_whitelist(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_device_fp ON device_ban(fingerprint)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_client_id ON oauth_clients(client_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_code ON oauth_auth_codes(code)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_code_client ON oauth_auth_codes(client_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_token_jti ON oauth_tokens(access_jti)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_token_refresh ON oauth_tokens(refresh_token)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_token_client ON oauth_tokens(client_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_dev_code ON oauth_device_codes(device_code)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_dev_usercode ON oauth_device_codes(user_code)")
    print("  [OK] 索引")
    
    # 5. 创建 admin 用户
    admin_uid = uuid.uuid4().hex[:12]
    password = os.urandom(8).hex()
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    password_hash = hashed.decode('utf-8')
    
    cur.execute("SELECT id FROM users WHERE user_name = 'admin'")
    if not cur.fetchone():
        cur.execute("""
            INSERT INTO users (user_name, user_password, apikeys, balence, uid, is_admin, email, must_change_password)
            VALUES (?, ?, '', 999.99, ?, 1, '', 1)
        """, ('admin', password_hash, admin_uid))
        print(f"  [OK] admin 用户已创建")
    else:
        print(f"  [OK] admin 用户已存在")
    
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 40)
    print("数据库初始化完成！")
    print("=" * 40)
    print(f"管理员账号: admin")
    print(f"管理员密码: {password}")
    print(f"管理员余额: 999.99 元")

if __name__ == '__main__':
    init_complete_db()


def ensure_subsystem_tables():
    """创建安全子系统所需审计表（幂等，IF NOT EXISTS）。

    这些表由「上网行为管理 / 堡垒机 / 日志审计服务器 / 认证服务器」共用，
    必须在 Alembic 迁移之外也保证存在（init_database() 会无条件调用本函数）。
    仅 SQLite 后端在此创建；Postgres 由 Alembic 迁移负责。
    """
    from . import configs
    if (getattr(configs, "DB_TYPE", "sqlite") or "sqlite") != "sqlite":
        return
    import sqlite3
    _path = getattr(configs, "DB_PATH", db_path)
    conn = sqlite3.connect(_path)
    try:
        cur = conn.cursor()
        # 上网行为管理：全站访问留痕
        cur.execute("""
            CREATE TABLE IF NOT EXISTS web_access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_uid TEXT,
                user_name TEXT,
                client_ip TEXT,
                method TEXT,
                path TEXT,
                query TEXT,
                category TEXT,
                action TEXT,
                status INTEGER,
                bytes INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 堡垒机：特权访问会话
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bastion_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                operator TEXT,
                remote_ip TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                command_count INTEGER DEFAULT 0
            )
        """)
        # 堡垒机：逐条特权操作审计（含命令/参数/结果，用于回放）
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bastion_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                node_id TEXT,
                operator TEXT,
                target TEXT,
                command TEXT,
                args TEXT,
                result_ok INTEGER DEFAULT 1,
                output TEXT,
                risk TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 堡垒机：高危命令审批工单
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bastion_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT UNIQUE,
                operator TEXT,
                command TEXT,
                args TEXT,
                status TEXT DEFAULT 'pending',
                reviewer TEXT,
                note TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                decided_at TIMESTAMP
            )
        """)
        # 日志审计服务器：统一审计收口
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT,
                event_type TEXT,
                severity TEXT,
                user_uid TEXT,
                user_name TEXT,
                client_ip TEXT,
                node_id TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 通知铃铛：公告/系统通知的权威收件箱（与好友关系解耦）
        cur.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id              TEXT PRIMARY KEY,
                user_uid        TEXT NOT NULL,
                title           TEXT,
                body            TEXT,
                level           TEXT DEFAULT 'info',
                link            TEXT,
                announcement_id TEXT,
                is_read         INTEGER DEFAULT 0,
                created_at      TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_uid ON notifications(user_uid)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_uid_read ON notifications(user_uid, is_read)")
        conn.commit()
    finally:
        conn.close()

