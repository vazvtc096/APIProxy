"""兑换码：批量生成面额码，用户自助兑换到余额。

码格式 RD-xxxxxxxx-xxxxxxxx（32 字符随机十六进制两段，全库唯一索引防撞）。
核销用「条件更新 + rowcount」乐观锁：UPDATE ... WHERE redeemed_by IS NULL，
并发兑换同一码只有一方成功，余额入账与核销同一事务提交。
"""
import secrets
import logging

from . import db


def _get_conn():
    return db.get_conn()


def ensure_redeem_table():
    """幂等建表"""
    conn = _get_conn()
    from . import db as _db
    if _db.is_postgres():
        conn.set_autocommit(True)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS redeem_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            amount REAL NOT NULL,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            redeemed_by TEXT,
            redeemed_at TIMESTAMP,
            note TEXT DEFAULT ''
        )
    """)
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_redeem_code ON redeem_codes(code)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_redeem_redeemed_by ON redeem_codes(redeemed_by)")
    try:
        conn.commit()
    except Exception:
        pass
    conn.close()


ensure_redeem_table()


def generate_codes(count: int, amount: float, created_by: str, note: str = '') -> list:
    """批量生成兑换码，返回明文码列表（仅此刻可见，库里只存明文码本身）"""
    count = max(1, min(int(count), 500))
    amount = round(float(amount), 6)
    if amount <= 0:
        raise ValueError('amount must be positive')
    conn = _get_conn()
    codes = []
    try:
        with conn:
            cur = conn.cursor()
            for _ in range(count):
                for _retry in range(5):
                    code = 'RD-' + secrets.token_hex(8) + '-' + secrets.token_hex(8)
                    try:
                        cur.execute(
                            "INSERT INTO redeem_codes (code, amount, created_by, note) "
                            "VALUES (?, ?, ?, ?)",
                            (code, amount, created_by, str(note or '')[:200]))
                        codes.append(code)
                        break
                    except Exception:
                        continue  # 极小概率码撞唯一索引，重试
                else:
                    raise ValueError('failed to generate unique code')
            conn.commit()
    finally:
        conn.close()
    return codes


def list_codes(status: str = 'all', limit: int = 200) -> list:
    """列出兑换码（status: all | unused | used）"""
    limit = max(1, min(int(limit), 1000))
    conn = _get_conn()
    try:
        cur = conn.cursor()
        if status == 'unused':
            cur.execute(
                "SELECT * FROM redeem_codes WHERE redeemed_by IS NULL "
                "ORDER BY id DESC LIMIT ?", (limit,))
        elif status == 'used':
            cur.execute(
                "SELECT * FROM redeem_codes WHERE redeemed_by IS NOT NULL "
                "ORDER BY id DESC LIMIT ?", (limit,))
        else:
            cur.execute("SELECT * FROM redeem_codes ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def delete_code(code_id: int) -> tuple:
    """删除未使用的兑换码。返回 (ok, error)"""
    conn = _get_conn()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM redeem_codes WHERE id = ? AND redeemed_by IS NULL",
                        (code_id,))
            if cur.rowcount == 0:
                conn.rollback()
                return False, 'code not found or already redeemed'
            conn.commit()
        return True, ''
    finally:
        conn.close()


def redeem(code: str, user_name: str) -> tuple:
    """核销兑换码并入账余额（同一事务）。返回 (ok, message)"""
    code = str(code or '').strip()
    if not code:
        return False, 'code is required'
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT amount FROM redeem_codes WHERE code = ? AND redeemed_by IS NULL",
                    (code,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return False, '兑换码无效或已被使用'
        amount = float(row['amount'] if not isinstance(row, (list, tuple)) else row[0])
        cur.execute(
            "UPDATE redeem_codes SET redeemed_by = ?, redeemed_at = CURRENT_TIMESTAMP "
            "WHERE code = ? AND redeemed_by IS NULL", (user_name, code))
        if cur.rowcount != 1:
            conn.rollback()
            return False, '兑换码无效或已被使用'
        cur.execute("UPDATE users SET balence = COALESCE(balence, 0) + ? WHERE user_name = ?",
                    (amount, user_name))
        conn.commit()
        return True, f'兑换成功：+{amount:.4f} 元'
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logging.error(f"redeem failed: {e}")
        return False, 'redeem failed'
    finally:
        conn.close()
