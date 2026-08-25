import sqlite3
import os
import bcrypt
import uuid
import hashlib

try:
    from . import configs
except ImportError:
    import configs

# 数据库路径必须遵循 configs.DB_PATH（支持 DB_PATH 环境变量覆盖），
# 历史实现在此硬编码 users.db，导致自定义数据库位置时建表建错库。
db_path = getattr(configs, 'DB_PATH', None) or os.path.join(os.path.dirname(__file__), 'users.db')

def smart_init():
    from . import db as _db
    conn = _db.get_conn()
    # PostgreSQL：DDL 初始化切 autocommit，使单条语句失败不污染整事务
    # （对齐 sqlite3 行为；psycopg2 默认事务中止后后续全部 InFailedSqlTransaction）
    if _db.is_postgres():
        conn.set_autocommit(True)
    cur = conn.cursor()

    print("智能初始化数据库...\n")
    
    # 1. 检查 users 表
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cur.fetchone():
        print("创建 users 表...")
        cur.execute("""
            CREATE TABLE users (
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
                ban_expire_at REAL,
                email TEXT UNIQUE,
                last_device_type TEXT,
                last_device_os TEXT,
                max_sessions INTEGER DEFAULT 1,
                max_overdraft REAL DEFAULT 0.0,
                must_change_password INTEGER DEFAULT 0,
                last_active_time TIMESTAMP,
                login_count INTEGER DEFAULT 0,
                total_spent REAL DEFAULT 0.0
            )
        """)
    else:
        print("检查 users 表字段...")
        cur.execute("PRAGMA table_info(users)")
        existing = {col[1] for col in cur.fetchall()}
        
        needed = {
            'user_password': 'TEXT',
            'apikeys': "TEXT DEFAULT ''",
            'balence': 'REAL DEFAULT 0.0',
            'uid': 'TEXT UNIQUE',
            'created_at': "TEXT DEFAULT CURRENT_TIMESTAMP",
            'is_admin': 'INTEGER DEFAULT 0',
            'is_banned': 'INTEGER DEFAULT 0',
            'ban_reason': 'TEXT',
            'ban_expire_at': 'REAL',
            'email': 'TEXT',
            'last_login_ip': 'TEXT',
            'last_login_time': 'TIMESTAMP',
            'last_login_user_agent': 'TEXT',
            'last_device_type': 'TEXT',
            'last_device_os': 'TEXT',
            'max_sessions': 'INTEGER DEFAULT 1',
            'max_overdraft': 'REAL DEFAULT 0.0',
            'allow_overdraft': 'INTEGER DEFAULT 0',
            'must_change_password': 'INTEGER DEFAULT 0',
            'last_active_time': 'TIMESTAMP',
            'login_count': 'INTEGER DEFAULT 0',
            'total_spent': 'REAL DEFAULT 0.0',
        }
        
        for col, definition in needed.items():
            if col not in existing:
                print(f"  添加字段: {col}")
                try:
                    cur.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
                except Exception as e:
                    print(f"    跳过: {e}")
    
    # 2. recharge_requests 表
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='recharge_requests'")
    if not cur.fetchone():
        print("创建 recharge_requests 表...")
        cur.execute("""
            CREATE TABLE recharge_requests (
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
    
    
    # 4. login_logs 表（登录日志）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='login_logs'")
    if not cur.fetchone():
        print("创建 login_logs 表...")
        cur.execute("""
            CREATE TABLE login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_uid TEXT,
                user_name TEXT,
                login_ip TEXT,
                user_agent TEXT,
                status TEXT,
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    # 5. sessions 表（活跃会话）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
    if not cur.fetchone():
        print("创建 sessions 表...")
        cur.execute("""
            CREATE TABLE sessions (
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
    
    # 6. system_config 表（系统配置）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_config'")
    if not cur.fetchone():
        print("创建 system_config 表...")
        cur.execute("""
            CREATE TABLE system_config (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # 7. rcon_config 表（RCON 配置）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='rcon_config'")
    if not cur.fetchone():
        print("创建 rcon_config 表...")
        cur.execute("""
            CREATE TABLE rcon_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                rcon_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_refreshed_at TIMESTAMP
            )
        """)

    # 7.1 rcon_keys 表（RCON 多密钥管理）
    # 历史版本漏建此表，导致 /api/admin/rcon-keys（增/查/删）、RCON
    # list/create/revoke_rcon_key 命令以及 stats 命令全部 500。
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='rcon_keys'")
    if not cur.fetchone():
        print("创建 rcon_keys 表...")
        cur.execute("""
            CREATE TABLE rcon_keys (
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

    # 6.5 security_events 表（安全事件审计）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
    if not cur.fetchone():
        print("创建 security_events 表...")
        cur.execute("""
            CREATE TABLE security_events (
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

    # 6.6 ip_blacklist 表（IP 封禁名单）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_blacklist'")
    if not cur.fetchone():
        print("创建 ip_blacklist 表...")
        cur.execute("""
            CREATE TABLE ip_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                reason TEXT,
                ban_expire_at REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # 6.7 ip_whitelist 表（IP 白名单：仅 RCON 可控制，白名单 IP 不受拦截）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_whitelist'")
    if not cur.fetchone():
        print("创建 ip_whitelist 表...")
        cur.execute("""
            CREATE TABLE ip_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                note TEXT DEFAULT '',
                bypass TEXT DEFAULT 'all',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # 7. posts 表（社区帖子）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='posts'")
    if not cur.fetchone():
        print("创建 posts 表...")
        cur.execute("""
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id TEXT UNIQUE,
                user_uid TEXT,
                user_name TEXT,
                title TEXT,
                content TEXT,
                status TEXT DEFAULT 'pending',
                likes INTEGER DEFAULT 0,
                admin_remark TEXT,
                approved_by TEXT,
                approved_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    # 7.5 OAuth 2.0 相关表
    # 7.5.1 oauth_clients 表（OAuth 客户端注册信息）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_clients'")
    if not cur.fetchone():
        print("创建 oauth_clients 表...")
        cur.execute("""
            CREATE TABLE oauth_clients (
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

    # 7.5.2 oauth_auth_codes 表（授权码，含 PKCE）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_auth_codes'")
    if not cur.fetchone():
        print("创建 oauth_auth_codes 表...")
        cur.execute("""
            CREATE TABLE oauth_auth_codes (
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

    # 7.5.3 oauth_tokens 表（access/refresh token 记录，支持吊销与内省）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_tokens'")
    if not cur.fetchone():
        print("创建 oauth_tokens 表...")
        cur.execute("""
            CREATE TABLE oauth_tokens (
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

    # 7.5.4 oauth_device_codes 表（设备授权流 RFC 8628）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_device_codes'")
    if not cur.fetchone():
        print("创建 oauth_device_codes 表...")
        cur.execute("""
            CREATE TABLE oauth_device_codes (
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

    # 8. post_favorites 表（帖子收藏）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='post_favorites'")
    if not cur.fetchone():
        print("创建 post_favorites 表...")
        cur.execute("""
            CREATE TABLE post_favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_uid TEXT,
                post_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_uid, post_id)
            )
        """)
    
    # 9. friends 表（好友关系）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='friends'")
    if not cur.fetchone():
        print("创建 friends 表...")
        cur.execute("""
            CREATE TABLE friends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_uid TEXT,
                friend_uid TEXT,
                friend_name TEXT,
                status TEXT DEFAULT 'pending',
                remark TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                accepted_at TIMESTAMP
            )
        """)
    
    # 10. chat_messages 表（聊天消息）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chat_messages'")
    if not cur.fetchone():
        print("创建 chat_messages 表...")
        cur.execute("""
            CREATE TABLE chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                from_uid TEXT,
                from_name TEXT,
                to_uid TEXT,
                to_name TEXT,
                content TEXT,
                type TEXT DEFAULT 'text',
                amount REAL DEFAULT 0.0,
                status TEXT DEFAULT 'sent',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                claimed_at TIMESTAMP
            )
        """)
    
    # 11. balence_transactions 表（余额变动记录）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='balence_transactions'")
    if not cur.fetchone():
        print("创建 balence_transactions 表...")
        cur.execute("""
            CREATE TABLE balence_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE,
                user_uid TEXT,
                user_name TEXT,
                type TEXT,
                amount REAL,
                balence_after REAL,
                related_id TEXT,
                remark TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    # 12. scheduled_tasks 表（定时任务）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scheduled_tasks'")
    if not cur.fetchone():
        print("创建 scheduled_tasks 表...")
        cur.execute("""
            CREATE TABLE scheduled_tasks (
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
    
    # 13. task_execution_logs 表（任务执行日志）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='task_execution_logs'")
    if not cur.fetchone():
        print("创建 task_execution_logs 表...")
        cur.execute("""
            CREATE TABLE task_execution_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                result TEXT NOT NULL,
                output TEXT,
                duration_ms INTEGER
            )
        """)
    
    # 14. 创建索引
    print("创建索引...")
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_uid ON users(uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_recharge_user ON recharge_requests(user_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_recharge_status ON recharge_requests(status)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_login_user ON login_logs(user_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_login_time ON login_logs(created_at)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_name)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_post_favorites_user ON post_favorites(user_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_post_favorites_post ON post_favorites(post_id)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_friend ON friends(friend_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_friends_status ON friends(status)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_from ON chat_messages(from_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_to ON chat_messages(to_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_created ON chat_messages(created_at)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_user ON balence_transactions(user_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_created ON balence_transactions(created_at)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_enabled ON scheduled_tasks(is_enabled)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_next_run ON scheduled_tasks(next_run_at)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON scheduled_tasks(status)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tasks_behavior ON scheduled_tasks(behavior)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_task_id ON task_execution_logs(task_id)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_executed_at ON task_execution_logs(executed_at)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_result ON task_execution_logs(result)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_security_user ON security_events(user_uid)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_security_created ON security_events(created_at)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_security_severity ON security_events(severity)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ipblack_ip ON ip_blacklist(ip)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ipblack_expire ON ip_blacklist(ban_expire_at)")
    except: pass
    # 6.8 device_ban 表（设备指纹封禁，由 R3 批量请求规则写入）
    # 必须先建表再建 idx_device_fp 索引，否则索引创建失败会让 PG 事务中止
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='device_ban'")
    if not cur.fetchone():
        print("创建 device_ban 表...")
        cur.execute("""\n            CREATE TABLE device_ban (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                fingerprint TEXT UNIQUE,\n                reason TEXT,\n                ban_expire_at REAL,\n                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n            )\n        """)

    # 6.9 config_kv 表（通用键值配置，持久化可自定义封禁规则等）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='config_kv'")
    if not cur.fetchone():
        print("创建 config_kv 表...")
        cur.execute("""\n            CREATE TABLE config_kv (\n                key TEXT PRIMARY KEY,\n                value TEXT\n            )\n        """)
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ipwhite_ip ON ip_whitelist(ip)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_device_fp ON device_ban(fingerprint)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_client_id ON oauth_clients(client_id)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_code ON oauth_auth_codes(code)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_code_client ON oauth_auth_codes(client_id)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_token_jti ON oauth_tokens(access_jti)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_token_refresh ON oauth_tokens(refresh_token)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_token_client ON oauth_tokens(client_id)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_dev_code ON oauth_device_codes(device_code)")
    except: pass
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_dev_usercode ON oauth_device_codes(user_code)")
    except: pass
    print("  [OK] 索引创建完成")

    # 4.4.5 独立 apikeys 索引表（修复全表扫描 DoS）。该表历史由 apikey.py 的
    # _init_apikeys_table 建，但 smart_init 未调用它，导致下方 SELECT 报
    # "no such table: apikeys" 并使后续建表中断。此处补建，保证 smart_init 自洽。
    cur.execute("""
        CREATE TABLE IF NOT EXISTS apikeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            apikey_hash TEXT UNIQUE NOT NULL,
            owner_name TEXT NOT NULL,
            owner_uid TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON apikeys(apikey_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_apikeys_owner ON apikeys(owner_name)")

    # 4.5 迁移：将现有 users.apikeys 同步到索引表 apikeys（修复全表扫描 DoS）
    cur.execute("SELECT COUNT(*) FROM apikeys")
    if cur.fetchone()[0] == 0:
        cur.execute("SELECT user_name, uid, apikeys FROM users")
        migrated = 0
        for u in cur.fetchall():
            apikeys_str = u[2] or ''
            if apikeys_str:
                for k in apikeys_str.split(','):
                    k = k.strip()
                    if k:
                        kh = hashlib.sha256(k.encode('utf-8')).hexdigest()
                        try:
                            cur.execute(
                                "INSERT OR IGNORE INTO apikeys (apikey_hash, owner_name, owner_uid) VALUES (?, ?, ?)",
                                (kh, u[0], u[1])
                            )
                            migrated += 1
                        except Exception:
                            pass
        conn.commit()
        if migrated:
            print(f"  [OK] 已从 users.apikeys 迁移 {migrated} 个 API Key 到索引表")

    # 5. 给没有 uid 的用户生成 uid
    cur.execute("SELECT id, user_name FROM users WHERE uid IS NULL OR uid = ''")
    for row in cur.fetchall():
        new_uid = uuid.uuid4().hex[:12]
        cur.execute("UPDATE users SET uid = ? WHERE id = ?", (new_uid, row[0]))
        print(f"  生成 UID: {row[1]} -> {new_uid}")
    
    # 6. 创建 admin 用户（仅首次、admin 不存在时创建；之后启动绝不重置密码）
    cur.execute("SELECT id FROM users WHERE user_name = 'admin'")
    if not cur.fetchone():
        print("创建 admin 用户（首次初始化）...")
        admin_uid = uuid.uuid4().hex[:12]
        password = '123456'
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        cur.execute("""
            INSERT INTO users (user_name, user_password, apikeys, balence, uid, is_admin, email, max_overdraft, must_change_password)
            VALUES (?, ?, '', 999.99, ?, 1, '', 0.0, 1)
        """, ('admin', hashed.decode('utf-8'), admin_uid))
        print("\n" + "=" * 40)
        print("首次初始化完成！")
        print("账号: admin")
        print("密码: 123456")
        print("请登录后尽快修改密码。")
        print("=" * 40)
    else:
        # admin 已存在：保留其现有密码与配置，不做任何覆盖（避免被重置为弱密码）
        print("admin 用户已存在，跳过初始化（不修改现有密码）。")

    # ================== 15. 通知/公告 + 钩子引擎 + 用量统计 ==================
    # 15.1 chat_messages 增补字段：is_read（未读红点统一口径）、announcement_id（关联公告）
    cur.execute("PRAGMA table_info(chat_messages)")
    _chat_cols = {c[1] for c in cur.fetchall()}
    _chat_new = {
        'is_read': 'INTEGER DEFAULT 0',
        'announcement_id': 'TEXT',
    }
    _need_backfill_isread = 'is_read' not in _chat_cols
    for _col, _defn in _chat_new.items():
        if _col not in _chat_cols:
            print(f"  chat_messages 添加字段: {_col}")
            try:
                cur.execute(f"ALTER TABLE chat_messages ADD COLUMN {_col} {_defn}")
            except Exception as e:
                print(f"    跳过: {e}")
    if _need_backfill_isread:
        # 回填：历史上以 status='read' / read_at 标记的已读消息
        try:
            cur.execute(
                "UPDATE chat_messages SET is_read = 1 "
                "WHERE read_at IS NOT NULL OR status = 'read' OR status = 'claimed'"
            )
            print(f"  [OK] chat_messages.is_read 回填 {cur.rowcount} 条历史已读消息")
        except Exception as e:
            print(f"  is_read 回填跳过: {e}")

    # 15.2 friends 增补字段：is_protected（受保护好友关系，不允许删除，如内置 admin）
    cur.execute("PRAGMA table_info(friends)")
    _friend_cols = {c[1] for c in cur.fetchall()}
    if 'is_protected' not in _friend_cols:
        print("  friends 添加字段: is_protected")
        try:
            cur.execute("ALTER TABLE friends ADD COLUMN is_protected INTEGER DEFAULT 0")
        except Exception as e:
            print(f"    跳过: {e}")

    # 15.3 announcements 表（管理员公告，投递为聊天消息）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='announcements'")
    if not cur.fetchone():
        print("创建 announcements 表...")
        cur.execute("""
            CREATE TABLE announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                announcement_id TEXT UNIQUE,
                title TEXT,
                content TEXT,
                level TEXT DEFAULT 'info',
                target TEXT DEFAULT 'all',
                target_detail TEXT DEFAULT '',
                sender_uid TEXT,
                sender_name TEXT,
                recipients INTEGER DEFAULT 0,
                pinned INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # 15.4 hooks 表（事件钩子：事件名 + 条件 + 动作 DSL）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hooks'")
    if not cur.fetchone():
        print("创建 hooks 表...")
        cur.execute("""
            CREATE TABLE hooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hook_id TEXT UNIQUE,
                name TEXT,
                description TEXT DEFAULT '',
                events TEXT NOT NULL,
                condition TEXT DEFAULT '',
                actions TEXT NOT NULL,
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

    # 15.5 hook_logs 表（钩子执行日志）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hook_logs'")
    if not cur.fetchone():
        print("创建 hook_logs 表...")
        cur.execute("""
            CREATE TABLE hook_logs (
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

    # 15.6 usage_logs 表（每次 API 调用的用量与费用明细，统计图数据源）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usage_logs'")
    if not cur.fetchone():
        print("创建 usage_logs 表...")
        cur.execute("""
            CREATE TABLE usage_logs (
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

    # 15.7 post_collections 表（帖子收藏，social.py 使用 uid 列名口径）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='post_collections'")
    if not cur.fetchone():
        print("创建 post_collections 表...")
        cur.execute("""
            CREATE TABLE post_collections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid TEXT,
                post_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(uid, post_id)
            )
        """)

    # 15.8 为全部存量用户补建与 admin 的双向好友关系（受保护，不可删除）
    cur.execute("SELECT uid, user_name FROM users WHERE user_name = 'admin'")
    _admin_row = cur.fetchone()
    if _admin_row and _admin_row[0]:
        _admin_uid, _admin_name = _admin_row[0], _admin_row[1]
        cur.execute("SELECT uid, user_name FROM users WHERE uid IS NOT NULL AND uid != '' AND uid != ?", (_admin_uid,))
        _all_users = cur.fetchall()
        _added = 0
        for _uid, _uname in _all_users:
            # 正向：用户 -> admin
            cur.execute(
                "SELECT id, status, is_protected FROM friends WHERE user_uid = ? AND friend_uid = ?",
                (_uid, _admin_uid)
            )
            _r = cur.fetchone()
            if not _r:
                cur.execute(
                    "INSERT INTO friends (user_uid, friend_uid, friend_name, status, is_protected, accepted_at) "
                    "VALUES (?, ?, ?, 'accepted', 1, CURRENT_TIMESTAMP)",
                    (_uid, _admin_uid, _admin_name)
                )
                _added += 1
            else:
                cur.execute(
                    "UPDATE friends SET status = 'accepted', is_protected = 1, friend_name = ? WHERE id = ?",
                    (_admin_name, _r[0])
                )
            # 反向：admin -> 用户
            cur.execute(
                "SELECT id FROM friends WHERE user_uid = ? AND friend_uid = ?",
                (_admin_uid, _uid)
            )
            _r2 = cur.fetchone()
            if not _r2:
                cur.execute(
                    "INSERT INTO friends (user_uid, friend_uid, friend_name, status, is_protected, accepted_at) "
                    "VALUES (?, ?, ?, 'accepted', 1, CURRENT_TIMESTAMP)",
                    (_admin_uid, _uid, _uname)
                )
                _added += 1
            else:
                cur.execute(
                    "UPDATE friends SET status = 'accepted', is_protected = 1, friend_name = ? WHERE id = ?",
                    (_uname, _r2[0])
                )
        print(f"  [OK] admin 默认好友关系已就绪（新增 {_added} 条，覆盖 {len(_all_users)} 个用户）")
    else:
        print("  admin 用户 uid 缺失，跳过默认好友补建")

    # 15.9 回填 users.login_count（按历史成功登录日志统计，仅首次迁移时执行）
    try:
        cur.execute("SELECT value FROM system_config WHERE key = 'login_count_backfill_v1'")
        if not cur.fetchone():
            cur.execute("""
                UPDATE users SET login_count = (
                    SELECT COUNT(*) FROM login_logs l
                    WHERE l.user_uid = users.uid AND l.status = 'success'
                )
                WHERE uid IS NOT NULL AND uid != ''
            """)
            cur.execute("INSERT OR REPLACE INTO system_config (key, value) VALUES ('login_count_backfill_v1', '1')")
            print("  [OK] users.login_count 已按历史登录日志回填")
    except Exception as e:
        print(f"  login_count 回填跳过: {e}")

    # 15.10 新增表索引
    for _idx_sql in (
        "CREATE INDEX IF NOT EXISTS idx_chat_unread ON chat_messages(to_uid, is_read)",
        "CREATE INDEX IF NOT EXISTS idx_chat_ann ON chat_messages(announcement_id)",
        "CREATE INDEX IF NOT EXISTS idx_ann_created ON announcements(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_hooks_enabled ON hooks(is_enabled)",
        "CREATE INDEX IF NOT EXISTS idx_hooks_hook_id ON hooks(hook_id)",
        "CREATE INDEX IF NOT EXISTS idx_hooklogs_hook ON hook_logs(hook_id)",
        "CREATE INDEX IF NOT EXISTS idx_hooklogs_created ON hook_logs(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_hooklogs_event ON hook_logs(event_name)",
        "CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_logs(user_uid)",
        "CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_logs(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_usage_model ON usage_logs(model)",
        "CREATE INDEX IF NOT EXISTS idx_usage_user_created ON usage_logs(user_uid, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_postcoll_uid ON post_collections(uid)",
        "CREATE INDEX IF NOT EXISTS idx_friends_protected ON friends(is_protected)",
    ):
        try:
            cur.execute(_idx_sql)
        except Exception as e:
            print(f"  索引跳过: {e}")
    print("  [OK] 通知/钩子/用量统计相关表与索引已就绪")

    # 6.1 确保内置公开 OAuth 客户端 'default' 存在（无客户端/公共客户端模式使用，强制 PKCE，授予全部非管理员 scope）
    DEFAULT_SCOPES = 'api profile openid email posts:read posts:write friends:read friends:write chat:read chat:write transactions:read transactions:write apikeys:read apikeys:write user:read user:write'
    cur.execute("SELECT id FROM oauth_clients WHERE client_id = 'default'")
    if not cur.fetchone():
        print("创建内置默认 OAuth 客户端 'default'（公开客户端，强制 PKCE）...")
        cur.execute("""
            INSERT INTO oauth_clients
            (client_id, client_secret_hash, client_name, owner_name, redirect_uris, grant_types, scopes, is_confidential, token_endpoint_auth_method)
            VALUES ('default', '', '本账户直接授权', 'system', '', 'authorization_code', ?, 0, 'none')
        """, (DEFAULT_SCOPES,))
    else:
        # 已存在：确保 scope 已扩展到最新全集（兼容旧库仅含 'api' 的情况）
        print("内置默认 OAuth 客户端 'default' 已存在，同步最新 scope ...")
        cur.execute("UPDATE oauth_clients SET scopes = ? WHERE client_id = 'default'", (DEFAULT_SCOPES,))

    # 6.3 价格表迁 DB：model_prices（支持自动扩展上游模型 + 管理员动态定价）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS model_prices (
            model  TEXT PRIMARY KEY,
            input  REAL NOT NULL DEFAULT 0,
            output REAL NOT NULL DEFAULT 0,
            priced INTEGER NOT NULL DEFAULT 0
        )
    """)
    # 从 token_price_config.json 种入已知模型（priced=1，表示已实现精确定价）
    try:
        import json as _json
        import os as _os
        _pcfg_path = _os.path.join(_os.path.dirname(__file__), 'token_price_config.json')
        with open(_pcfg_path, 'r', encoding='utf-8') as _f:
            _pcfg = _json.load(_f)
        _mpmt = _pcfg.get('money_per_million_tokens', {})
        for _m, _p in _mpmt.items():
            _inp = float(_p.get('input', 0))
            _out = float(_p.get('output', 0))
            cur.execute(
                "INSERT OR IGNORE INTO model_prices (model, input, output, priced) VALUES (?, ?, ?, 1)",
                (_m, _inp, _out)
            )
        print(f"  价格表已就绪：{len(_mpmt)} 个预置模型（来自 token_price_config.json）")
    except Exception as _e:
        print(f"  价格表种入跳过：{_e}")

    # 6.3b 时段计费表：pricing_schedules（按时段切换峰/谷价，DB 可编辑）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pricing_schedules'")
    if not cur.fetchone():
        print("创建 pricing_schedules 表...")
        # start/end 是 PG 保留字，须用双引号标识符（SQLite 同样支持）
        cur.execute("""
            CREATE TABLE pricing_schedules (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                model   TEXT NOT NULL,
                "start" TEXT NOT NULL,
                "end"   TEXT NOT NULL,
                input   REAL NOT NULL,
                output  REAL NOT NULL,
                enabled INTEGER DEFAULT 1,
                UNIQUE(model, "start", "end")
            )
        """)
    # 首次迁移：若表为空，从 configs.PRICING['models'] 的 schedules 种入
    try:
        cur.execute("SELECT COUNT(*) FROM pricing_schedules")
        if cur.fetchone()[0] == 0:
            _pc = getattr(configs, 'PRICING', {}) or {}
            _pmodels = _pc.get('models') or {}
            _sn = 0
            for _m, _e in _pmodels.items():
                if not isinstance(_e, dict):
                    continue
                _scheds = _e.get('schedules')
                if not isinstance(_scheds, list):
                    continue
                for _s in _scheds:
                    if not isinstance(_s, dict):
                        continue
                    cur.execute(
                        'INSERT OR IGNORE INTO pricing_schedules (model, "start", "end", input, output, enabled) VALUES (?, ?, ?, ?, ?, 1)',
                        (_m, str(_s.get('start', '')), str(_s.get('end', '')),
                         float(_s.get('input', 0)), float(_s.get('output', 0)))
                    )
                    _sn += 1
            if _sn:
                print(f"  [OK] 已从 config.yaml 导入 {_sn} 条时段计费到 pricing_schedules 表")
    except Exception as e:
        print(f"  pricing_schedules 首次导入跳过：{e}")

    # ② 清理 BufPay 残留的 orders 表（如库中存在）
    try:
        cur.execute("DROP TABLE IF EXISTS orders")
        print("  [OK] 已清理 BufPay orders 表（如存在）")
    except Exception as e:
        print(f"  orders 表清理跳过: {e}")

    # 6.10 上游配置表（多上游 API Key 管理，替代直接改 config.yaml）
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='upstreams'")
    if not cur.fetchone():
        print("创建 upstreams 表...")
        cur.execute("""
            CREATE TABLE upstreams (
                name TEXT PRIMARY KEY,
                base_url TEXT NOT NULL,
                api_key TEXT NOT NULL,
                priority INTEGER DEFAULT 100,
                enabled INTEGER DEFAULT 1,
                disabled_models TEXT DEFAULT ''
            )
        """)
    # 首次迁移：若 upstreams 表为空，将 config.yaml 的 upstreams 导入 DB（之后以 DB 为准）
    try:
        cur.execute("SELECT COUNT(*) FROM upstreams")
        if cur.fetchone()[0] == 0:
            _ups = getattr(configs, 'UPSTREAMS', []) or []
            _n = 0
            for u in _ups:
                if not isinstance(u, dict) or not u.get('name'):
                    continue
                cur.execute(
                    "INSERT OR IGNORE INTO upstreams (name, base_url, api_key, priority, enabled, disabled_models) VALUES (?, ?, ?, ?, ?, ?)",
                    (u.get('name'), u.get('base_url', ''), u.get('api_key', ''),
                     int(u.get('priority', 100)), 1 if u.get('enabled', True) else 0,
                     ','.join([str(x) for x in (u.get('disabled_models', []) or [])]))
                )
                _n += 1
            if _n:
                print(f"  [OK] 已从 config.yaml 导入 {_n} 个上游到 upstreams 表")
    except Exception as e:
        print(f"  upstreams 首次导入跳过：{e}")

    # ③ 强制管理员改密（默认停用）：历史上曾一次性标记全部管理员需改密，
    #    但自用场景下该拦截会在聊天/管理操作处报 403 且无前端引导，体验差。
    #    现已停用自动标记（后端 _enforce_must_change_password 中间件仍保留，
    #    若将来需要可手动 UPDATE users SET must_change_password=1 对个别账号启用）。
    try:
        cur.execute("SELECT value FROM system_config WHERE key = 'admin_force_pw_v1'")
        if not cur.fetchone():
            # 仅在历史库存在该标记时清理，避免残留旧标记继续拦截
            cur.execute("UPDATE users SET must_change_password = 0 WHERE is_admin = 1")
            cur.execute("INSERT OR REPLACE INTO system_config (key, value) VALUES ('admin_force_pw_v1', '1')")
            print("  [OK] 已清除历史管理员强制改密标记（该机制已停用）")
    except Exception as e:
        print(f"  管理员改密标记清理跳过: {e}")

    conn.commit()
    # 回收空间（SQLite 专属，需在事务外执行；PostgreSQL 由 autovacuum 自动处理）
    try:
        if not _db.is_postgres():
            cur.execute("VACUUM")
    except Exception:
        pass
    conn.close()

if __name__ == '__main__':
    smart_init()
