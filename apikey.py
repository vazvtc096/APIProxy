import sqlite3
import secrets
import uuid
import os
import base64
import hashlib
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .configs import DB_PATH


def _hash_apikey(apikey: str) -> str:
    """对 API Key 做 SHA256 哈希，仅存储哈希值，避免明文泄露"""
    return hashlib.sha256(apikey.encode('utf-8')).hexdigest()


def _init_apikeys_table():
    """初始化独立的 apikeys 表，apikey_hash 建唯一索引，避免全表扫描（修复 DoS 风险）"""
    conn = _get_conn()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS apikeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apikey_hash TEXT UNIQUE NOT NULL,
                owner_name TEXT NOT NULL,
                owner_uid TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON apikeys(apikey_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_apikeys_owner ON apikeys(owner_name)")


def _get_conn():
    """获取数据库连接（SQLite / PostgreSQL，经 db 抽象层统一）"""
    from . import db
    return db.get_conn()


def _init_db():
    """初始化数据库表
    - uid: 用户唯一标识符（UUID），对外展示用
    - user_password: 改为哈希存储（pbkdf2:sha256）
    """
    conn = _get_conn()
    from . import db as _db
    # DDL 初始化切 autocommit（对齐 smart_init：单语句失败不污染整事务；
    # PG 上 ALTER 已存在列抛 DuplicateColumn，autocommit 使其不中止后续语句）
    if _db.is_postgres():
        conn.set_autocommit(True)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT UNIQUE,
            user_name TEXT NOT NULL UNIQUE,
            user_password TEXT,
            apikeys TEXT,
            balence REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # 兼容旧数据库：若列不存在则补建（smart_init 已建则跳过）
    # catch Exception：SQLite 抛 OperationalError，PG 抛 DuplicateColumn，均需吞掉
    for _col, _defn in (
        ("uid", "TEXT"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("allow_overdraft", "INTEGER DEFAULT 0"),
    ):
        try:
            cur.execute(f"ALTER TABLE users ADD COLUMN {_col} {_defn}")
        except Exception:
            pass  # 列已存在
    try:
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_uid ON users(uid)")
    except Exception:
        pass
    conn.close()


_init_db()
_init_apikeys_table()


# ---------- 密码工具函数 ----------
SCRYPT_N = 2**17      # CPU/内存成本
SCRYPT_R = 8          # 块大小
SCRYPT_P = 1          # 并行度
SCRYPT_LEN = 64       # 派生密钥长度（字节）


def _scrypt_hash(password: str, salt: bytes) -> bytes:
    """使用 cryptography Scrypt 派生密钥"""
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def hash_password(password: str) -> str:
    """生成密码哈希（优先使用 cryptography Scrypt，兼容 bcrypt）
    存储格式：$scrypt$base64_salt$base64_hash
    """
    salt = os.urandom(32)
    key = _scrypt_hash(password, salt)
    encoded_key = base64.b64encode(key).decode('ascii')
    encoded_salt = base64.b64encode(salt).decode('ascii')
    return f'$scrypt${encoded_salt}${encoded_key}'


def verify_password(password: str, password_hash: str) -> bool:
    """验证密码哈希
    支持多种哈希格式：
    1. Scrypt ($scrypt$ 开头) — cryptography 优先格式
    2. bcrypt ($2b$ / $2a$ / $2y$ 开头)
    3. Werkzeug pbkdf2 (pbkdf2: 开头)
    不再支持明文密码验证（已确认数据库中无明文残留）。
    """
    if not password_hash:
        return password is None or password == ''

    # 1. 尝试 Scrypt 验证（cryptography）
    if password_hash.startswith('$scrypt$'):
        try:
            parts = password_hash.split('$')
            if len(parts) != 4:
                return False
            salt = base64.b64decode(parts[2])
            stored_key = base64.b64decode(parts[3])
            derived_key = _scrypt_hash(password, salt)
            return derived_key == stored_key
        except Exception:
            return False
    
    # 2. 尝试 bcrypt 验证
    if password_hash.startswith('$2'):
        try:
            pwd_bytes = password.encode('utf-8')
            # bcrypt 限制 72 字节，超长密码先做 sha256
            if len(pwd_bytes) > 72:
                import hashlib
                pwd_bytes = hashlib.sha256(pwd_bytes).digest()
            return bcrypt.checkpw(pwd_bytes, password_hash.encode('utf-8'))
        except Exception:
            return False
    
    # 3. 尝试 Werkzeug pbkdf2 验证
    if password_hash.startswith('pbkdf2:'):
        try:
            from werkzeug.security import check_password_hash
            return check_password_hash(password_hash, password)
        except Exception:
            return False
    
    # 不再支持明文密码：未知哈希格式一律拒绝
    return False


def generate_uid() -> str:
    """生成用户 UID（短 UUID 格式，8 位十六进制）"""
    return uuid.uuid4().hex[:12]


# ---------- 用户查询辅助函数 ----------
def _get_user_by_name(owner: str) -> dict | None:
    """根据用户名查询用户（返回字典或 None）"""
    conn = _get_conn()
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_name = ?", (owner,))
        row = cursor.fetchone()
        return dict(row) if row else None


def _verify_user_password(user: dict, password: str | None) -> bool:
    """验证用户密码
    - 如果用户密码为 None，传入 password 也必须为 None
    - 如果用户有密码，必须验证通过
    """
    stored_pwd = user.get('user_password')
    if stored_pwd is None:
        return password is None
    if password is None:
        return False
    return verify_password(password, stored_pwd)


def _gen_and_save_apikey(owner: str, user: dict) -> str:
    """生成唯一的 API Key 并保存到数据库（内部辅助函数）"""
    had_apikeys = (user['apikeys'] or '').split(',') if user['apikeys'] else []
    
    # 数量限制：每个用户最多 10 个 API Key
    if len(had_apikeys) >= 10:
        raise ValueError("Maximum 10 API keys per user")
    
    for _ in range(10):
        new_apikey = APIKey._generate_apikey(owner)
        if new_apikey not in had_apikeys:
            break
    else:
        raise ValueError("Failed to generate a unique API key after 10 attempts")

    had_apikeys.append(new_apikey)
    new_apikeys_str = ','.join(had_apikeys)

    conn = _get_conn()
    with conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET apikeys = ? WHERE user_name = ?",
            (new_apikeys_str, owner)
        )
        # 同步写入索引表（仅存哈希，防明文泄露）
        cursor.execute(
            "INSERT OR IGNORE INTO apikeys (apikey_hash, owner_name, owner_uid) VALUES (?, ?, ?)",
            (_hash_apikey(new_apikey), owner, user.get('uid'))
        )
        conn.commit()

    return new_apikey


class APIKey:
    @staticmethod
    def _valid_format(apikey: str):
        """验证 API Key 格式
        新格式：sk- + 48 位十六进制（24 字节熵，完全随机）
        兼容旧格式：sk- + 32 位十六进制（旧版带用户名前缀）
        """
        if not isinstance(apikey, str):
            return False
        if not apikey.startswith("sk-"):
            return False
        key_part = apikey[3:]
        # 接受 48 位（新格式）或 32 位（旧格式兼容）
        if len(key_part) not in (32, 48):
            return False
        return all(c in "0123456789abcdef" for c in key_part)

    @staticmethod
    def exists_in_db(apikey: str, owner: str, password: str = None):
        """检查 API Key 是否属于指定用户（带密码验证）"""
        user = _get_user_by_name(owner)
        if not user:
            return False
        if not _verify_user_password(user, password):
            return False
        apikeys_str = user.get('apikeys') or ''
        apikeys = apikeys_str.split(',') if apikeys_str else []
        return apikey in apikeys

    @staticmethod
    def _generate_apikey(owner: str = None):
        """生成 API Key：48 位完全随机十六进制（24 字节熵）
        完全随机，无可预测前缀，防止枚举攻击
        """
        return "sk-" + secrets.token_hex(24)

    @staticmethod
    def _require_apikey(owner: str, password: str = None):
        """为用户生成新的 API Key（带密码验证）"""
        user = _get_user_by_name(owner)
        if user:
            # 用户已存在，验证密码
            if not _verify_user_password(user, password):
                raise ValueError("Invalid password")
        else:
            # 用户不存在，创建新用户（自动生成 UID）
            conn = _get_conn()
            with conn:
                cursor = conn.cursor()
                new_uid = generate_uid()
                pwd_hash = hash_password(password) if password else None
                cursor.execute(
                    "INSERT INTO users (uid, user_name, user_password, apikeys, balence) VALUES (?, ?, ?, '', 0)",
                    (new_uid, owner, pwd_hash)
                )
                conn.commit()
            user = _get_user_by_name(owner)

        return _gen_and_save_apikey(owner, user)

    @staticmethod
    def _require_apikey_trusted(owner: str):
        """可信环境下生成 API Key（已登录用户，无需密码验证）
        注意：调用前必须确保用户已通过身份验证
        """
        user = _get_user_by_name(owner)
        if not user:
            raise ValueError("User not found")
        return _gen_and_save_apikey(owner, user)

    @staticmethod
    def _get_user_by_apikey(apikey: str) -> dict | None:
        """通过 API Key 查找用户（优先走索引表，避免全表扫描；回退兼容旧数据）"""
        if not isinstance(apikey, str):
            return None
        apikey_hash = _hash_apikey(apikey)
        # 优先走索引表（O(1) 查询）
        try:
            conn = _get_conn()
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT u.* FROM users u JOIN apikeys ak ON u.user_name = ak.owner_name WHERE ak.apikey_hash = ?",
                    (apikey_hash,)
                )
                row = cursor.fetchone()
                if row:
                    return dict(row)
        except Exception:
            pass
        # 回退：兼容尚未迁移的旧数据（全表扫描）
        conn = _get_conn()
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
            rows = cursor.fetchall()
        for row in rows:
            apikeys_str = row['apikeys'] or ''
            apikeys = apikeys_str.split(',') if apikeys_str else []
            if apikey in apikeys:
                return dict(row)
        return None

    @classmethod
    def from_apikey(cls, apikey: str):
        """通过 API Key 直接构造对象（trusted 模式，无需密码验证）
        用于 API 端点认证场景：知道 API Key 即视为已认证
        """
        if not cls._valid_format(apikey):
            raise ValueError("Invalid API key format")
        user = cls._get_user_by_apikey(apikey)
        if not user:
            raise ValueError("Invalid API key")
        obj = super().__new__(cls)
        obj.apikey = apikey
        obj.owner = user['user_name']
        obj._trusted = True  # 标记为可信模式，跳过后续密码验证
        obj.password = None
        return obj

    def __new__(cls, owner: str, password: str = None, apikey: str = None, _create: bool = False):
        if _create:
            obj = super().__new__(cls)
            obj.apikey = cls._require_apikey(owner, password)
            return obj
        else:
            if apikey is None:
                raise ValueError("API key must be provided when _create is False")
            if not cls._valid_format(apikey):
                raise ValueError("Invalid API key format")
            if not cls.exists_in_db(apikey, owner, password):
                raise ValueError("API key does not exist in the database")
            obj = super().__new__(cls)
            obj.apikey = apikey
            obj._trusted = False
            return obj

    def __init__(self, owner: str, password: str = None, apikey: str = None, _create: bool = False):
        self.owner = owner
        self.password = password
        if not _create:
            if apikey is not None:
                self.apikey = apikey

    def __str__(self):
        return self.apikey if self.apikey else ""

    def __repr__(self):
        return f"APIKey(owner='{self.owner}', apikey='{self.apikey}')"

    def delete(self):
        """删除当前 API Key"""
        if self.apikey is None:
            return
        user = _get_user_by_name(self.owner)
        if not user:
            return
        # trusted 模式或密码验证通过
        if not getattr(self, '_trusted', False) and not _verify_user_password(user, self.password):
            return
        if user['apikeys']:
            had_apikeys = user['apikeys'].split(',')
            if self.apikey in had_apikeys:
                had_apikeys.remove(self.apikey)
                new_apikeys_str = ','.join(had_apikeys)
                conn = _get_conn()
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE users SET apikeys = ? WHERE user_name = ?",
                        (new_apikeys_str, self.owner)
                    )
                    # 从索引表删除
                    cursor.execute(
                        "DELETE FROM apikeys WHERE apikey_hash = ? AND owner_name = ?",
                        (_hash_apikey(self.apikey), self.owner)
                    )
                    conn.commit()
        self.apikey = None

    @property
    def balence(self):
        """获取用户余额（trusted 模式或密码验证通过）"""
        if self.apikey is None:
            return 0.0
        user = _get_user_by_name(self.owner)
        if not user:
            return 0.0
        # trusted 模式或密码验证通过
        if not getattr(self, '_trusted', False) and not _verify_user_password(user, self.password):
            return 0.0
        return user['balence'] or 0.0

    @balence.setter
    def balence(self, value: float):
        """设置用户余额（trusted 模式或密码验证通过）"""
        user = _get_user_by_name(self.owner)
        if not user:
            return
        # trusted 模式或密码验证通过
        if not getattr(self, '_trusted', False) and not _verify_user_password(user, self.password):
            return
        conn = _get_conn()
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET balence = ? WHERE user_name = ?",
                (value, self.owner)
            )
            conn.commit()

    @property
    def max_overdraft(self):
        """获取用户最大允许超支金额（trusted 模式或密码验证通过）"""
        if self.apikey is None:
            return 0.0
        user = _get_user_by_name(self.owner)
        if not user:
            return 0.0
        # trusted 模式或密码验证通过
        if not getattr(self, '_trusted', False) and not _verify_user_password(user, self.password):
            return 0.0
        return user.get('max_overdraft', 0.0) or 0.0

    @max_overdraft.setter
    def max_overdraft(self, value: float):
        """设置用户最大允许超支金额（trusted 模式或密码验证通过）"""
        if value < 0:
            value = 0.0
        user = _get_user_by_name(self.owner)
        if not user:
            return
        # trusted 模式或密码验证通过
        if not getattr(self, '_trusted', False) and not _verify_user_password(user, self.password):
            return
        conn = _get_conn()
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET max_overdraft = ? WHERE user_name = ?",
                (value, self.owner)
            )
            conn.commit()

    def deduct_balence(self, amount: float) -> dict:
        """扣除余额，支持超支
        总是扣除费用（实际以模型返回为准），余额可以为负数
        返回: {'success': bool, 'new_balence': float, 'overdraft': float, 'over_limit': bool, 'message': str}
        """
        if amount <= 0:
            return {'success': False, 'new_balence': self.balence, 'overdraft': 0, 'over_limit': False, 'message': '扣款金额必须大于 0'}
        
        current_balence = self.balence
        new_balence = round(current_balence - amount, 6)
        overdraft = max(0.0, -new_balence)
        max_od = self.max_overdraft
        
        # 是否超过超支限额
        over_limit = overdraft > max_od
        
        # 总是执行扣款（实际以模型返回为准）
        self.balence = new_balence
        
        if over_limit:
            message = f'扣款成功，扣除 {amount:.6f} 元，剩余余额 {new_balence:.6f} 元（超支 {overdraft:.6f} 元，已超过限额 {max_od:.6f} 元）'
        elif overdraft > 0:
            message = f'扣款成功，扣除 {amount:.6f} 元，剩余余额 {new_balence:.6f} 元（超支 {overdraft:.6f} 元）'
        else:
            message = f'扣款成功，扣除 {amount:.6f} 元，剩余余额 {new_balence:.6f} 元'
        
        return {
            'success': True,
            'new_balence': new_balence,
            'overdraft': overdraft,
            'over_limit': over_limit,
            'message': message
        }

    @property
    def uid(self):
        """获取用户 UID"""
        user = _get_user_by_name(self.owner)
        return user['uid'] if user else None
    
    @property
    def allow_overdraft(self):
        """获取用户是否允许超支"""
        user = _get_user_by_name(self.owner)
        if not user:
            return False
        # trusted 模式或密码验证通过
        if not getattr(self, '_trusted', False) and not _verify_user_password(user, self.password):
            return False
        return bool(user.get('allow_overdraft', 0))
    
    @allow_overdraft.setter
    def allow_overdraft(self, value: bool):
        """设置用户是否允许超支"""
        user = _get_user_by_name(self.owner)
        if not user:
            return
        # trusted 模式或密码验证通过
        if not getattr(self, '_trusted', False) and not _verify_user_password(user, self.password):
            return
        conn = _get_conn()
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET allow_overdraft = ? WHERE user_name = ?",
                (1 if value else 0, self.owner)
            )
            conn.commit()
