"""事件钩子引擎（管理员可配置的小型 DSL）

设计目标
--------
管理员在后台配置「事件名 + 条件 + 动作」三元组，事件在业务流程中被触发时，
引擎按优先级依次求值条件，条件为真则顺序执行动作。

DSL 语法（Python 子集，安全求值，不 eval/exec 原生代码）
------------------------------------------------------
事件名：  USER_LOGIN, USER_REGISTER            （逗号分隔，任一匹配即触发）
条件：    TRIGGER_USER.loginCount <= 1 and TRIGGER_USER.isAdmin == 0
动作：    send_message(TRIGGER_USER, "你好 %s", TRIGGER_USER.userName); add_balence(TRIGGER_USER, 1.5)

- 条件支持：比较、and/or/not、in/not in、算术、括号、常量、内置常量成员访问、
  少量内置函数（len/int/float/str/abs/min/max/round/now/lower/upper/contains 等）。
- 动作支持：函数调用（可 ; 分隔多个），参数可为常量、内置常量、成员访问、
  以及 "%s" 风格的格式化（由动作实现内部处理，与 Python % 语义一致）。
- 完全禁止：import、attribute 写入、下标赋值、lambda、推导式、赋值、
  访问以 _ 开头的属性、访问未白名单的名称。

安全实现
--------
使用 ast.parse(mode='eval') 解析，再用显式白名单遍历器求值。
任何未在白名单内的 AST 节点 → HookError，绝不 fallback 到 eval()。
"""

from __future__ import annotations

import ast
import asyncio
import datetime
import json
import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence

__all__ = [
    'HookError',
    'EVENT_CATALOG',
    'STATIC_MEMBERS',
    'DYNAMIC_MEMBERS',
    'USER_FIELD_MAP',
    'init_hooks',
    'fire_event',
    'evaluate_condition',
    'run_actions',
    'validate_hook',
    'list_hooks',
    'get_hook',
    'create_hook',
    'update_hook',
    'delete_hook',
    'test_hook',
    'hook_meta',
    'list_hook_logs',
]


class HookError(Exception):
    """DSL 解析 / 求值 / 执行错误"""


# ---------------------------------------------------------------- 事件目录
# 事件名 -> (中文说明, 该事件提供的动态常量列表)
EVENT_CATALOG: Dict[str, Dict[str, Any]] = {
    'USER_REGISTER':     {'desc': '用户注册成功',       'vars': ['TRIGGER_USER']},
    'USER_LOGIN':        {'desc': '用户登录成功',       'vars': ['TRIGGER_USER', 'CLIENT_IP']},
    'USER_LOGIN_FAILED': {'desc': '用户登录失败',       'vars': ['TRIGGER_USER', 'CLIENT_IP', 'REASON']},
    'USER_BANNED':       {'desc': '用户被封禁',         'vars': ['TRIGGER_USER', 'TARGET_USER', 'REASON']},
    'USER_UNBANNED':     {'desc': '用户被解封',         'vars': ['TRIGGER_USER', 'TARGET_USER']},
    'API_CALL':          {'desc': 'API 调用完成',       'vars': ['TRIGGER_USER', 'MODEL', 'TOKENS', 'COST']},
    'API_CALL_FAILED':   {'desc': 'API 调用失败',       'vars': ['TRIGGER_USER', 'MODEL', 'REASON']},
    'BALENCE_LOW':       {'desc': '余额低于阈值',       'vars': ['TRIGGER_USER', 'AMOUNT']},
    'BALENCE_CHANGE':    {'desc': '余额发生变动',       'vars': ['TRIGGER_USER', 'AMOUNT']},
    'RECHARGE_REQUEST':  {'desc': '提交充值申请',       'vars': ['TRIGGER_USER', 'AMOUNT']},
    'RECHARGE_APPROVED': {'desc': '充值申请通过',       'vars': ['TRIGGER_USER', 'TARGET_USER', 'AMOUNT']},
    'RECHARGE_REJECTED': {'desc': '充值申请被拒',       'vars': ['TRIGGER_USER', 'TARGET_USER', 'AMOUNT', 'REASON']},
    'POST_CREATE':       {'desc': '发布新帖子',         'vars': ['TRIGGER_USER', 'POST_ID', 'CONTENT']},
    'POST_APPROVED':     {'desc': '帖子审核通过',       'vars': ['TRIGGER_USER', 'TARGET_USER', 'POST_ID']},
    'POST_REJECTED':     {'desc': '帖子审核被拒',       'vars': ['TRIGGER_USER', 'TARGET_USER', 'POST_ID', 'REASON']},
    'MESSAGE_SEND':      {'desc': '发送聊天消息',       'vars': ['TRIGGER_USER', 'TARGET_USER', 'CONTENT']},
    'FRIEND_REQUEST':    {'desc': '发送好友请求',       'vars': ['TRIGGER_USER', 'TARGET_USER']},
    'FRIEND_ACCEPTED':   {'desc': '好友请求被接受',     'vars': ['TRIGGER_USER', 'TARGET_USER']},
    'TRANSFER':          {'desc': '好友转账',           'vars': ['TRIGGER_USER', 'TARGET_USER', 'AMOUNT']},
    'REDPACKET':         {'desc': '发送红包',           'vars': ['TRIGGER_USER', 'TARGET_USER', 'AMOUNT']},
    'REDPACKET_CLAIM':   {'desc': '领取红包',           'vars': ['TRIGGER_USER', 'TARGET_USER', 'AMOUNT']},
    'APIKEY_CREATE':     {'desc': '创建 API Key',       'vars': ['TRIGGER_USER']},
    'ANNOUNCEMENT_SEND': {'desc': '管理员发送公告',     'vars': ['TRIGGER_USER', 'CONTENT']},
    'SECURITY_EVENT':    {'desc': '安全事件（WAF等）',  'vars': ['TRIGGER_USER', 'CLIENT_IP', 'REASON']},
}

# 4.1 静态内置成员（方法）：名称 -> 说明与签名，供前端提示
STATIC_MEMBERS: Dict[str, Dict[str, str]] = {
    'send_message':   {'sig': 'send_message(user, text, *args)',      'desc': '以系统身份给用户发私信，text 支持 %s 占位'},
    'send':           {'sig': 'send(user, text, *args)',              'desc': 'send_message 的简写别名'},
    'add_balence':    {'sig': 'add_balence(user, amount, remark="")', 'desc': '增加用户余额（负数为扣减）并记账'},
    'sub_balence':    {'sig': 'sub_balence(user, amount, remark="")', 'desc': '扣减用户余额并记账'},
    'set_balence':    {'sig': 'set_balence(user, amount)',            'desc': '直接设置用户余额'},
    'ban_user':       {'sig': 'ban_user(user, reason="", minutes=0)', 'desc': '封禁用户，minutes=0 表示永久'},
    'unban_user':     {'sig': 'unban_user(user)',                     'desc': '解除封禁'},
    'send_announcement': {'sig': 'send_announcement(title, content)', 'desc': '向全体用户广播公告'},
    'set_max_sessions': {'sig': 'set_max_sessions(user, n)',          'desc': '设置用户最大同时在线设备数'},
    'log':            {'sig': 'log(text, *args)',                     'desc': '写入钩子执行日志（调试用）'},
    'notify_admin':   {'sig': 'notify_admin(text, *args)',            'desc': '给所有管理员发私信'},
    'block_ip':       {'sig': 'block_ip(ip, reason="", minutes=0)',   'desc': '将 IP 加入黑名单'},
}

# 4.2 动态内置成员（常量）：名称 -> 说明
DYNAMIC_MEMBERS: Dict[str, str] = {
    'TRIGGER_USER': '触发事件的用户对象',
    'TARGET_USER':  '事件作用的目标用户对象（可能为空）',
    'EVENT_NAME':   '当前事件名，字符串',
    'EVENT_TIME':   '事件发生时间，字符串 YYYY-MM-DD HH:MM:SS',
    'CLIENT_IP':    '客户端 IP（登录/安全类事件）',
    'AMOUNT':       '金额（充值/转账/红包/余额变动）',
    'MODEL':        '模型名（API 调用事件）',
    'TOKENS':       'token 总数（API 调用事件）',
    'COST':         '本次费用（API 调用事件）',
    'CONTENT':      '内容文本（帖子/消息/公告）',
    'POST_ID':      '帖子 ID',
    'REASON':       '原因说明',
}

# 用户对象成员：DSL 里的 camelCase -> 数据库列名
USER_FIELD_MAP: Dict[str, str] = {
    'uid': 'uid',
    'userName': 'user_name',
    'name': 'user_name',
    'email': 'email',
    'balence': 'balence',
    'balance': 'balence',
    'isAdmin': 'is_admin',
    'isBanned': 'is_banned',
    'banReason': 'ban_reason',
    'loginCount': 'login_count',
    'totalSpent': 'total_spent',
    'createdAt': 'created_at',
    'lastLoginIp': 'last_login_ip',
    'lastLoginTime': 'last_login_time',
    'lastDeviceType': 'last_device_type',
    'lastDeviceOs': 'last_device_os',
    'maxSessions': 'max_sessions',
    'maxOverdraft': 'max_overdraft',
    'allowOverdraft': 'allow_overdraft',
    'lastActiveTime': 'last_active_time',
}


# ---------------------------------------------------------------- 值包装
class UserRef:
    """DSL 中的用户对象：支持 camelCase 成员访问，底层是 users 表的一行 dict"""

    __slots__ = ('_data',)

    def __init__(self, data: Optional[dict]):
        self._data = dict(data) if data else {}

    @property
    def uid(self) -> str:
        return str(self._data.get('uid') or '')

    @property
    def user_name(self) -> str:
        return str(self._data.get('user_name') or '')

    @property
    def is_empty(self) -> bool:
        return not self._data

    def member(self, name: str) -> Any:
        if name.startswith('_'):
            raise HookError(f'不允许访问私有成员: {name}')
        col = USER_FIELD_MAP.get(name)
        if col is None:
            # 允许直接用下划线列名访问，方便高级用法
            if name in USER_FIELD_MAP.values():
                col = name
            else:
                raise HookError(
                    f'用户对象没有成员 "{name}"，可用成员: ' + ', '.join(sorted(USER_FIELD_MAP))
                )
        val = self._data.get(col)
        if val is None:
            # 数值型缺省为 0，方便 <= 比较；文本型缺省为空串
            if col in ('balence', 'login_count', 'total_spent', 'is_admin', 'is_banned',
                       'max_sessions', 'max_overdraft', 'allow_overdraft'):
                return 0
            return ''
        return val

    def __str__(self) -> str:
        return self.user_name or self.uid

    def __repr__(self) -> str:
        return f'<User {self.user_name}:{self.uid}>'

    def __bool__(self) -> bool:
        return bool(self._data)


# ---------------------------------------------------------------- 安全求值器
_ALLOWED_BINOPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    ast.Pow: lambda a, b: a ** b,
}

_ALLOWED_CMPOPS = {
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}

_MAX_EXPR_LEN = 4000
_MAX_POW = 1000       # 防 2**999999 内存炸弹
_MAX_STR_MUL = 10000


def _safe_pure_funcs() -> Dict[str, Callable]:
    """条件与参数表达式中可用的纯函数（无副作用）"""
    def _contains(hay, needle):
        return str(needle) in str(hay)

    def _now(fmt: str = '%Y-%m-%d %H:%M:%S'):
        return datetime.datetime.now().strftime(str(fmt))

    def _hour():
        return datetime.datetime.now().hour

    def _weekday():
        return datetime.datetime.now().weekday()

    def _fmt(tpl, *args):
        return _apply_format(str(tpl), args)

    return {
        'len': lambda x: len(x),
        'int': lambda x: int(x),
        'float': lambda x: float(x),
        'str': lambda x: str(x),
        'bool': lambda x: bool(x),
        'abs': lambda x: abs(x),
        'min': min,
        'max': max,
        'round': lambda x, n=0: round(x, int(n)),
        'lower': lambda s: str(s).lower(),
        'upper': lambda s: str(s).upper(),
        'strip': lambda s: str(s).strip(),
        'contains': _contains,
        'startswith': lambda s, p: str(s).startswith(str(p)),
        'endswith': lambda s, p: str(s).endswith(str(p)),
        'now': _now,
        'hour': _hour,
        'weekday': _weekday,
        'format': _fmt,
    }


def _apply_format(tpl: str, args: Sequence[Any]) -> str:
    """按 Python % 语义格式化；参数数量不匹配时降级为拼接，避免钩子因格式错误整体失败"""
    if not args:
        return tpl
    vals = tuple(str(a) if isinstance(a, UserRef) else a for a in args)
    try:
        return tpl % vals
    except (TypeError, ValueError):
        try:
            return tpl % vals[0] if len(vals) == 1 else tpl + ' ' + ' '.join(str(v) for v in vals)
        except Exception:
            return tpl + ' ' + ' '.join(str(v) for v in vals)


class _Evaluator:
    """白名单 AST 求值器：只支持表达式，无赋值/无语句/无属性写入"""

    def __init__(self, ctx: Dict[str, Any], funcs: Dict[str, Callable]):
        self.ctx = ctx
        self.funcs = funcs

    # -- 入口 --
    def eval_expr(self, source: str) -> Any:
        source = (source or '').strip()
        if not source:
            raise HookError('表达式为空')
        if len(source) > _MAX_EXPR_LEN:
            raise HookError(f'表达式过长（上限 {_MAX_EXPR_LEN} 字符）')
        try:
            tree = ast.parse(source, mode='eval')
        except SyntaxError as e:
            raise HookError(f'语法错误: {e.msg}（第 {e.offset} 列）') from None
        return self._visit(tree.body)

    # -- 分派 --
    def _visit(self, node: ast.AST) -> Any:
        method = getattr(self, '_v_' + type(node).__name__, None)
        if method is None:
            raise HookError(f'不支持的语法元素: {type(node).__name__}')
        return method(node)

    # -- 字面量 --
    def _v_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, (str, int, float, bool)) or node.value is None:
            return node.value
        raise HookError('不支持的常量类型')

    def _v_Tuple(self, node: ast.Tuple) -> tuple:
        return tuple(self._visit(e) for e in node.elts)

    def _v_List(self, node: ast.List) -> list:
        if len(node.elts) > 200:
            raise HookError('列表元素过多（上限 200）')
        return [self._visit(e) for e in node.elts]

    def _v_Set(self, node: ast.Set) -> set:
        return {self._visit(e) for e in node.elts}

    def _v_Dict(self, node: ast.Dict) -> dict:
        return {self._visit(k): self._visit(v) for k, v in zip(node.keys, node.values)}

    # -- 名称 --
    def _v_Name(self, node: ast.Name) -> Any:
        name = node.id
        if name.startswith('_'):
            raise HookError(f'不允许访问 "{name}"')
        if name in self.ctx:
            return self.ctx[name]
        if name in self.funcs:
            return self.funcs[name]
        if name in ('True', 'true'):
            return True
        if name in ('False', 'false'):
            return False
        if name in ('None', 'null'):
            return None
        known = sorted(set(list(self.ctx) + list(self.funcs)))
        raise HookError(f'未定义的名称 "{name}"，可用: ' + ', '.join(known))

    # -- 成员访问（只读，且仅限白名单对象） --
    def _v_Attribute(self, node: ast.Attribute) -> Any:
        if not isinstance(node.ctx, ast.Load):
            raise HookError('不允许写入属性')
        obj = self._visit(node.value)
        attr = node.attr
        if attr.startswith('_'):
            raise HookError(f'不允许访问私有属性 "{attr}"')
        if isinstance(obj, UserRef):
            return obj.member(attr)
        if isinstance(obj, dict):
            if attr in obj:
                return obj[attr]
            raise HookError(f'对象没有成员 "{attr}"')
        if isinstance(obj, str):
            safe = {'length': len(obj)}
            if attr in safe:
                return safe[attr]
        raise HookError(f'类型 {type(obj).__name__} 不支持成员访问')

    # -- 下标（只读，仅 list/tuple/dict/str） --
    def _v_Subscript(self, node: ast.Subscript) -> Any:
        if not isinstance(node.ctx, ast.Load):
            raise HookError('不允许下标赋值')
        obj = self._visit(node.value)
        if not isinstance(obj, (list, tuple, dict, str)):
            raise HookError('该类型不支持下标访问')
        key = self._visit(node.slice)
        try:
            return obj[key]
        except Exception as e:
            raise HookError(f'下标访问失败: {e}') from None

    # -- 运算 --
    def _v_BinOp(self, node: ast.BinOp) -> Any:
        op = _ALLOWED_BINOPS.get(type(node.op))
        if op is None:
            raise HookError(f'不支持的运算符: {type(node.op).__name__}')
        left = self._visit(node.left)
        right = self._visit(node.right)
        if isinstance(node.op, ast.Pow):
            try:
                if abs(float(right)) > _MAX_POW:
                    raise HookError('幂运算指数过大')
            except (TypeError, ValueError):
                raise HookError('幂运算参数非法') from None
        if isinstance(node.op, ast.Mult) and isinstance(left, str) or \
           isinstance(node.op, ast.Mult) and isinstance(right, str):
            n = right if isinstance(left, str) else left
            try:
                if abs(int(n)) > _MAX_STR_MUL:
                    raise HookError('字符串重复次数过大')
            except (TypeError, ValueError):
                pass
        if isinstance(left, UserRef):
            left = str(left)
        if isinstance(right, UserRef):
            right = str(right)
        try:
            return op(left, right)
        except HookError:
            raise
        except Exception as e:
            raise HookError(f'运算失败: {e}') from None

    def _v_UnaryOp(self, node: ast.UnaryOp) -> Any:
        val = self._visit(node.operand)
        if isinstance(node.op, ast.Not):
            return not val
        if isinstance(node.op, ast.USub):
            return -val
        if isinstance(node.op, ast.UAdd):
            return +val
        raise HookError(f'不支持的一元运算符: {type(node.op).__name__}')

    def _v_BoolOp(self, node: ast.BoolOp) -> Any:
        if isinstance(node.op, ast.And):
            result = True
            for v in node.values:
                result = self._visit(v)
                if not result:
                    return result
            return result
        if isinstance(node.op, ast.Or):
            result = False
            for v in node.values:
                result = self._visit(v)
                if result:
                    return result
            return result
        raise HookError('不支持的布尔运算符')

    def _v_Compare(self, node: ast.Compare) -> Any:
        left = self._visit(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            fn = _ALLOWED_CMPOPS.get(type(op))
            if fn is None:
                raise HookError(f'不支持的比较运算符: {type(op).__name__}')
            right = self._visit(comparator)
            lv = str(left) if isinstance(left, UserRef) else left
            rv = str(right) if isinstance(right, UserRef) else right
            # 数字与数字字符串的宽松比较，避免 DB 里 TEXT 存数字导致条件不成立
            lv, rv = _coerce_pair(lv, rv)
            try:
                ok = fn(lv, rv)
            except TypeError as e:
                raise HookError(f'比较失败: {e}') from None
            if not ok:
                return False
            left = right
        return True

    def _v_IfExp(self, node: ast.IfExp) -> Any:
        return self._visit(node.body) if self._visit(node.test) else self._visit(node.orelse)

    # -- 调用（纯函数，条件里可用；动作调用走 run_actions） --
    def _v_Call(self, node: ast.Call) -> Any:
        if not isinstance(node.func, ast.Name):
            raise HookError('只允许调用内置函数名')
        name = node.func.id
        fn = self.funcs.get(name)
        if fn is None:
            raise HookError(f'未知函数 "{name}"，可用: ' + ', '.join(sorted(self.funcs)))
        if node.keywords and any(k.arg is None for k in node.keywords):
            raise HookError('不支持 **kwargs 展开')
        args = [self._visit(a) for a in node.args]
        kwargs = {k.arg: self._visit(k.value) for k in node.keywords}
        try:
            return fn(*args, **kwargs)
        except HookError:
            raise
        except Exception as e:
            raise HookError(f'调用 {name} 失败: {e}') from None

    def _v_Starred(self, node: ast.Starred) -> Any:
        raise HookError('不支持 * 展开')


def _coerce_pair(a: Any, b: Any):
    """数字/数字字符串宽松比较"""
    if isinstance(a, bool) or isinstance(b, bool):
        return a, b
    if isinstance(a, (int, float)) and isinstance(b, str):
        try:
            return a, float(b)
        except ValueError:
            return a, b
    if isinstance(b, (int, float)) and isinstance(a, str):
        try:
            return float(a), b
        except ValueError:
            return a, b
    return a, b


# ---------------------------------------------------------------- 运行时依赖注入
_db_query: Optional[Callable] = None          # async_db_query(sql, args=None, fetch_one=False)
_gen_id: Optional[Callable] = None            # 生成 message_id
_notify: Optional[Callable] = None            # 可选：外部推送
_ADMIN_UID_CACHE: Dict[str, Any] = {'uid': None, 'name': 'admin', 'ts': 0.0}


def init_hooks(db_query: Callable, message_id_gen: Optional[Callable] = None,
               notifier: Optional[Callable] = None) -> None:
    """注入依赖，避免与 __main__ 循环导入"""
    global _db_query, _gen_id, _notify
    _db_query = db_query
    _gen_id = message_id_gen or (lambda: 'msg_' + uuid.uuid4().hex[:16])
    _notify = notifier
    logging.info('[hooks] 钩子引擎已初始化')


def _require_db() -> Callable:
    if _db_query is None:
        raise HookError('钩子引擎未初始化（init_hooks 未调用）')
    return _db_query


async def _get_admin() -> Dict[str, str]:
    """取内置 admin（缓存 60s），公告与系统消息以其身份发出"""
    now = time.time()
    if _ADMIN_UID_CACHE['uid'] and now - _ADMIN_UID_CACHE['ts'] < 60:
        return {'uid': _ADMIN_UID_CACHE['uid'], 'user_name': _ADMIN_UID_CACHE['name']}
    db = _require_db()
    rows = await db("SELECT uid, user_name FROM users WHERE user_name = 'admin' LIMIT 1")
    if not rows:
        rows = await db("SELECT uid, user_name FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1")
    if rows:
        _ADMIN_UID_CACHE.update({'uid': rows[0]['uid'], 'name': rows[0]['user_name'], 'ts': now})
        return {'uid': rows[0]['uid'], 'user_name': rows[0]['user_name']}
    return {'uid': 'system', 'user_name': '系统'}


async def _load_user(ref: Any) -> Optional[dict]:
    """把 DSL 值解析为 users 表一行：支持 UserRef / uid / 用户名 / dict"""
    if ref is None:
        return None
    if isinstance(ref, UserRef):
        if ref._data.get('uid'):
            return ref._data
        ref = ref.user_name
    if isinstance(ref, dict):
        return ref
    key = str(ref).strip()
    if not key:
        return None
    db = _require_db()
    rows = await db("SELECT * FROM users WHERE uid = ? OR user_name = ? LIMIT 1", (key, key))
    return rows[0] if rows else None


# ---------------------------------------------------------------- 动作实现
class _ActionRunner:
    """动作执行器：收集调用意图（同步求值）→ 由 run_actions 异步执行"""

    def __init__(self, ctx: Dict[str, Any]):
        self.ctx = ctx
        self.calls: List[tuple] = []

    def _record(self, name: str):
        def _fn(*args, **kwargs):
            if len(self.calls) >= 20:
                raise HookError('单个钩子最多执行 20 个动作')
            self.calls.append((name, args, kwargs))
            return None
        return _fn

    def action_funcs(self) -> Dict[str, Callable]:
        return {name: self._record(name) for name in _ACTION_IMPLS}


async def _act_send_message(ctx, user, text, *args, **kw) -> str:
    db = _require_db()
    target = await _load_user(user)
    if not target:
        return 'send_message: 目标用户不存在'
    admin = await _get_admin()
    content = _apply_format(str(text), args)
    if len(content) > 2000:
        content = content[:2000]
    msg_id = _gen_id() if _gen_id else 'msg_' + uuid.uuid4().hex[:16]
    await db(
        """INSERT INTO chat_messages
           (message_id, from_uid, from_name, to_uid, to_name, content, type, status, is_read, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'system', 'sent', 0, CURRENT_TIMESTAMP)""",
        (msg_id, admin['uid'], admin['user_name'], target['uid'], target.get('user_name', ''), content)
    )
    return f"send_message -> {target.get('user_name')}: {content[:60]}"


async def _act_add_balence(ctx, user, amount, remark='hook', **kw) -> str:
    db = _require_db()
    target = await _load_user(user)
    if not target:
        return 'add_balence: 目标用户不存在'
    try:
        delta = float(amount)
    except (TypeError, ValueError):
        raise HookError('add_balence 金额非法')
    if abs(delta) > 100000:
        raise HookError('add_balence 金额超出安全上限（100000）')
    await db("UPDATE users SET balence = COALESCE(balence, 0) + ? WHERE uid = ?", (delta, target['uid']))
    rows = await db("SELECT balence FROM users WHERE uid = ?", (target['uid'],))
    after = rows[0]['balence'] if rows else 0
    await db(
        """INSERT INTO balence_transactions
           (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
           VALUES (?, ?, ?, 'hook_adjust', ?, ?, '', ?)""",
        ('tx_' + uuid.uuid4().hex[:16], target['uid'], target.get('user_name', ''),
         delta, after, str(remark)[:200])
    )
    return f"add_balence -> {target.get('user_name')}: {delta:+.4f} (余额 {after:.4f})"


async def _act_sub_balence(ctx, user, amount, remark='hook', **kw) -> str:
    try:
        delta = float(amount)
    except (TypeError, ValueError):
        raise HookError('sub_balence 金额非法')
    return await _act_add_balence(ctx, user, -abs(delta), remark)


async def _act_set_balence(ctx, user, amount, **kw) -> str:
    db = _require_db()
    target = await _load_user(user)
    if not target:
        return 'set_balence: 目标用户不存在'
    try:
        val = float(amount)
    except (TypeError, ValueError):
        raise HookError('set_balence 金额非法')
    if val < -100000 or val > 1000000:
        raise HookError('set_balence 金额超出安全范围')
    await db("UPDATE users SET balence = ? WHERE uid = ?", (val, target['uid']))
    await db(
        """INSERT INTO balence_transactions
           (transaction_id, user_uid, user_name, type, amount, balence_after, related_id, remark)
           VALUES (?, ?, ?, 'hook_set', ?, ?, '', 'hook set_balence')""",
        ('tx_' + uuid.uuid4().hex[:16], target['uid'], target.get('user_name', ''), val, val)
    )
    return f"set_balence -> {target.get('user_name')}: {val:.4f}"


async def _act_ban_user(ctx, user, reason='', minutes=0, **kw) -> str:
    db = _require_db()
    target = await _load_user(user)
    if not target:
        return 'ban_user: 目标用户不存在'
    if target.get('is_admin'):
        return 'ban_user: 拒绝封禁管理员账户'
    try:
        mins = int(minutes)
    except (TypeError, ValueError):
        mins = 0
    if mins > 0:
        expire = (datetime.datetime.now() + datetime.timedelta(minutes=mins)).strftime('%Y-%m-%d %H:%M:%S')
        await db("UPDATE users SET is_banned = 1, ban_reason = ?, ban_expire_at = ? WHERE uid = ?",
                 (str(reason)[:200], expire, target['uid']))
        return f"ban_user -> {target.get('user_name')} ({mins} 分钟)"
    await db("UPDATE users SET is_banned = 1, ban_reason = ?, ban_expire_at = NULL WHERE uid = ?",
             (str(reason)[:200], target['uid']))
    return f"ban_user -> {target.get('user_name')} (永久)"


async def _act_unban_user(ctx, user, **kw) -> str:
    db = _require_db()
    target = await _load_user(user)
    if not target:
        return 'unban_user: 目标用户不存在'
    await db("UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expire_at = NULL WHERE uid = ?",
             (target['uid'],))
    return f"unban_user -> {target.get('user_name')}"


async def _act_set_max_sessions(ctx, user, n, **kw) -> str:
    db = _require_db()
    target = await _load_user(user)
    if not target:
        return 'set_max_sessions: 目标用户不存在'
    try:
        val = max(1, min(int(n), 5))
    except (TypeError, ValueError):
        raise HookError('set_max_sessions 参数非法')
    await db("UPDATE users SET max_sessions = ? WHERE uid = ?", (val, target['uid']))
    return f"set_max_sessions -> {target.get('user_name')}: {val}"


async def _act_send_announcement(ctx, title, content='', **kw) -> str:
    from . import announcements as _ann  # 延迟导入，避免循环
    admin = await _get_admin()
    n = await _ann.broadcast_announcement(
        title=str(title)[:200],
        content=str(content)[:5000] or str(title)[:5000],
        level='info',
        sender_uid=admin['uid'],
        sender_name=admin['user_name'],
        target='all',
    )
    return f'send_announcement -> {n} 人'


async def _act_notify_admin(ctx, text, *args, **kw) -> str:
    db = _require_db()
    admins = await db("SELECT uid, user_name FROM users WHERE is_admin = 1")
    admin = await _get_admin()
    content = _apply_format(str(text), args)[:2000]
    cnt = 0
    for a in admins or []:
        msg_id = _gen_id() if _gen_id else 'msg_' + uuid.uuid4().hex[:16]
        await db(
            """INSERT INTO chat_messages
               (message_id, from_uid, from_name, to_uid, to_name, content, type, status, is_read, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'system', 'sent', 0, CURRENT_TIMESTAMP)""",
            (msg_id, admin['uid'], admin['user_name'], a['uid'], a['user_name'], content)
        )
        cnt += 1
    return f'notify_admin -> {cnt} 位管理员'


async def _act_block_ip(ctx, ip, reason='', minutes=0, **kw) -> str:
    db = _require_db()
    ip = str(ip).strip()
    if not ip:
        return 'block_ip: IP 为空'
    try:
        mins = int(minutes)
    except (TypeError, ValueError):
        mins = 0
    expire = None
    if mins > 0:
        expire = time.time() + mins * 60
    await db(
        "INSERT OR REPLACE INTO ip_blacklist (ip, reason, ban_expire_at) VALUES (?, ?, ?)",
        (ip, str(reason)[:200] or 'hook', expire)
    )
    return f'block_ip -> {ip}' + (f' ({mins} 分钟)' if mins else ' (永久)')


async def _act_log(ctx, text, *args, **kw) -> str:
    return 'log: ' + _apply_format(str(text), args)[:500]


_ACTION_IMPLS: Dict[str, Callable] = {
    'send_message': _act_send_message,
    'send': _act_send_message,
    'add_balence': _act_add_balence,
    'add_balance': _act_add_balence,
    'sub_balence': _act_sub_balence,
    'sub_balance': _act_sub_balence,
    'set_balence': _act_set_balence,
    'set_balance': _act_set_balence,
    'ban_user': _act_ban_user,
    'unban_user': _act_unban_user,
    'set_max_sessions': _act_set_max_sessions,
    'send_announcement': _act_send_announcement,
    'notify_admin': _act_notify_admin,
    'block_ip': _act_block_ip,
    'log': _act_log,
}


# ---------------------------------------------------------------- 上下文构建
async def build_context(event_name: str, payload: Optional[dict] = None) -> Dict[str, Any]:
    """把事件 payload 转成 DSL 上下文（动态内置成员）"""
    payload = payload or {}
    ctx: Dict[str, Any] = {
        'EVENT_NAME': event_name,
        'EVENT_TIME': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'CLIENT_IP': str(payload.get('client_ip') or ''),
        'AMOUNT': _num(payload.get('amount')),
        'MODEL': str(payload.get('model') or ''),
        'TOKENS': _num(payload.get('tokens')),
        'COST': _num(payload.get('cost')),
        'CONTENT': str(payload.get('content') or ''),
        'POST_ID': str(payload.get('post_id') or ''),
        'REASON': str(payload.get('reason') or ''),
    }

    trigger = payload.get('trigger_user')
    target = payload.get('target_user')
    ctx['TRIGGER_USER'] = UserRef(await _resolve_user_arg(trigger))
    ctx['TARGET_USER'] = UserRef(await _resolve_user_arg(target))
    # 额外自定义字段（不覆盖内置）
    for k, v in (payload.get('extra') or {}).items():
        key = str(k).upper()
        if key not in ctx and key.isidentifier():
            ctx[key] = v
    return ctx


async def _resolve_user_arg(val: Any) -> Optional[dict]:
    if val is None:
        return None
    if isinstance(val, dict):
        # 已是 users 行；若缺列则回查一次，保证 loginCount 等成员可用
        if 'login_count' in val or 'balence' in val:
            return val
        return await _load_user(val.get('uid') or val.get('user_name'))
    return await _load_user(val)


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------- 条件 / 动作
def evaluate_condition(condition: str, ctx: Dict[str, Any]) -> bool:
    """求值条件表达式。空条件视为恒真。"""
    cond = (condition or '').strip()
    if not cond:
        return True
    ev = _Evaluator(ctx, _safe_pure_funcs())
    result = ev.eval_expr(cond)
    if isinstance(result, UserRef):
        return bool(result)
    return bool(result)


def _split_actions(actions: str) -> List[str]:
    """按顶层 ; 分割动作，忽略字符串与括号内的分号"""
    out: List[str] = []
    buf: List[str] = []
    depth = 0
    quote: Optional[str] = None
    esc = False
    for ch in actions or '':
        if esc:
            buf.append(ch)
            esc = False
            continue
        if quote:
            buf.append(ch)
            if ch == '\\':
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            buf.append(ch)
            continue
        if ch in '([{':
            depth += 1
            buf.append(ch)
            continue
        if ch in ')]}':
            depth -= 1
            buf.append(ch)
            continue
        if ch == ';' and depth == 0:
            seg = ''.join(buf).strip()
            if seg:
                out.append(seg)
            buf = []
            continue
        if ch == '\n' and depth == 0:
            seg = ''.join(buf).strip()
            if seg:
                out.append(seg)
            buf = []
            continue
        buf.append(ch)
    tail = ''.join(buf).strip()
    if tail:
        out.append(tail)
    if quote:
        raise HookError('动作中有未闭合的引号')
    if depth != 0:
        raise HookError('动作中有未闭合的括号')
    return out


def _plan_actions(actions: str, ctx: Dict[str, Any]) -> List[tuple]:
    """解析动作为调用计划 [(name, args, kwargs), ...]，不产生任何副作用"""
    segments = _split_actions(actions)
    if not segments:
        raise HookError('动作为空')
    if len(segments) > 20:
        raise HookError('动作过多（上限 20）')
    runner = _ActionRunner(ctx)
    funcs = dict(_safe_pure_funcs())
    funcs.update(runner.action_funcs())
    ev = _Evaluator(ctx, funcs)
    for seg in segments:
        try:
            tree = ast.parse(seg, mode='eval')
        except SyntaxError as e:
            raise HookError(f'动作语法错误 "{seg[:40]}": {e.msg}') from None
        if not isinstance(tree.body, ast.Call):
            raise HookError(f'动作必须是函数调用: "{seg[:40]}"')
        if not isinstance(tree.body.func, ast.Name):
            raise HookError('动作只能调用内置方法名')
        fname = tree.body.func.id
        if fname not in _ACTION_IMPLS:
            raise HookError(
                f'未知动作 "{fname}"，可用动作: ' + ', '.join(sorted(_ACTION_IMPLS))
            )
        ev._visit(tree.body)
    return runner.calls


async def run_actions(actions: str, ctx: Dict[str, Any]) -> List[str]:
    """执行动作串，返回每个动作的结果描述"""
    plan = _plan_actions(actions, ctx)
    results: List[str] = []
    for name, args, kwargs in plan:
        impl = _ACTION_IMPLS.get(name)
        if impl is None:
            results.append(f'{name}: 未实现')
            continue
        try:
            res = await impl(ctx, *args, **kwargs)
            results.append(str(res))
        except HookError as e:
            results.append(f'{name}: 失败 - {e}')
        except Exception as e:
            logging.exception(f'[hooks] 动作 {name} 执行异常')
            results.append(f'{name}: 异常 - {e}')
    return results


def validate_hook(events: str, condition: str, actions: str) -> Dict[str, Any]:
    """静态校验：事件名、条件语法、动作语法。用 dry-run 上下文，不触碰数据库。"""
    errors: List[str] = []
    warnings: List[str] = []

    evs = [e.strip() for e in (events or '').replace('\n', ',').split(',') if e.strip()]
    if not evs:
        errors.append('至少需要一个事件名')
    for e in evs:
        if e not in EVENT_CATALOG:
            warnings.append(f'事件名 "{e}" 不在内置事件目录中（仍可保存，但不会被触发）')

    dry_ctx = _dry_context(evs[0] if evs else 'USER_LOGIN')
    if (condition or '').strip():
        try:
            _Evaluator(dry_ctx, _safe_pure_funcs()).eval_expr(condition)
        except HookError as ex:
            errors.append(f'条件错误: {ex}')
        except Exception as ex:
            errors.append(f'条件错误: {ex}')

    if not (actions or '').strip():
        errors.append('至少需要一个动作')
    else:
        try:
            plan = _plan_actions(actions, dry_ctx)
            if not plan:
                errors.append('动作解析结果为空')
        except HookError as ex:
            errors.append(f'动作错误: {ex}')
        except Exception as ex:
            errors.append(f'动作错误: {ex}')

    return {'ok': not errors, 'errors': errors, 'warnings': warnings, 'events': evs}


def _dry_context(event_name: str) -> Dict[str, Any]:
    """校验用的假上下文（不查库）"""
    fake_user = {
        'uid': 'dryrun000000', 'user_name': '示例用户', 'email': 'demo@example.com',
        'balence': 0.0, 'is_admin': 0, 'is_banned': 0, 'login_count': 0,
        'total_spent': 0.0, 'created_at': '2026-01-01 00:00:00', 'max_sessions': 1,
        'max_overdraft': 0.0, 'allow_overdraft': 0, 'ban_reason': '',
        'last_login_ip': '127.0.0.1', 'last_login_time': '', 'last_device_type': 'desktop',
        'last_device_os': '', 'last_active_time': '',
    }
    return {
        'EVENT_NAME': event_name,
        'EVENT_TIME': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'TRIGGER_USER': UserRef(fake_user),
        'TARGET_USER': UserRef(fake_user),
        'CLIENT_IP': '127.0.0.1',
        'AMOUNT': 0.0,
        'MODEL': 'demo-model',
        'TOKENS': 0.0,
        'COST': 0.0,
        'CONTENT': '',
        'POST_ID': '',
        'REASON': '',
    }


# ---------------------------------------------------------------- 触发入口
async def fire_event(event_name: str, payload: Optional[dict] = None,
                     wait: bool = False, **kwargs) -> Optional[List[dict]]:
    """触发事件。默认后台执行（不阻塞业务响应）；wait=True 时同步等待并返回结果。

    payload 可通过位置参数（dict）传入，也可通过关键字参数（**kwargs）传入
    以兼容旧的 ``fire_event('USER_LOGIN', trigger_user=..., client_ip=...)`` 调用风格；
    二者会合并（kwargs 优先），最终由 build_context 按 lowercase 键名读取。
    """
    if _db_query is None:
        return None
    if kwargs:
        payload = {**(payload or {}), **kwargs}
    if wait:
        return await _dispatch(event_name, payload)
    try:
        asyncio.get_running_loop().create_task(_dispatch_safe(event_name, payload))
    except RuntimeError:
        await _dispatch_safe(event_name, payload)
    return None


async def _dispatch_safe(event_name: str, payload: Optional[dict]):
    try:
        await _dispatch(event_name, payload)
    except Exception:
        logging.exception(f'[hooks] 事件 {event_name} 分发失败')


async def _dispatch(event_name: str, payload: Optional[dict]) -> List[dict]:
    db = _require_db()
    rows = await db(
        "SELECT * FROM hooks WHERE is_enabled = 1 ORDER BY priority ASC, id ASC"
    ) or []
    matched_hooks = []
    for h in rows:
        evs = {e.strip() for e in str(h.get('events') or '').replace('\n', ',').split(',') if e.strip()}
        if event_name in evs or '*' in evs:
            matched_hooks.append(h)
    if not matched_hooks:
        return []

    ctx = await build_context(event_name, payload)
    trigger: UserRef = ctx.get('TRIGGER_USER')  # type: ignore
    out: List[dict] = []

    for h in matched_hooks:
        started = time.perf_counter()
        matched = False
        results: List[str] = []
        err = ''
        try:
            matched = evaluate_condition(h.get('condition') or '', ctx)
            if matched:
                results = await run_actions(h.get('actions') or '', ctx)
        except HookError as e:
            err = str(e)
        except Exception as e:
            err = f'内部错误: {e}'
            logging.exception(f"[hooks] 钩子 {h.get('hook_id')} 执行异常")
        dur = int((time.perf_counter() - started) * 1000)

        try:
            await db(
                """INSERT INTO hook_logs
                   (hook_id, hook_name, event_name, trigger_uid, trigger_name,
                    matched, condition_text, result, error, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (h.get('hook_id'), h.get('name'), event_name,
                 trigger.uid if trigger else '', trigger.user_name if trigger else '',
                 1 if matched else 0, (h.get('condition') or '')[:500],
                 json.dumps(results, ensure_ascii=False)[:2000], err[:500], dur)
            )
            await db(
                """UPDATE hooks SET run_count = COALESCE(run_count,0) + 1,
                   match_count = COALESCE(match_count,0) + ?,
                   error_count = COALESCE(error_count,0) + ?,
                   last_run_at = CURRENT_TIMESTAMP, last_error = ?
                   WHERE hook_id = ?""",
                (1 if matched else 0, 1 if err else 0, err[:500], h.get('hook_id'))
            )
        except Exception:
            logging.exception('[hooks] 写入钩子日志失败')

        out.append({
            'hook_id': h.get('hook_id'), 'name': h.get('name'),
            'matched': matched, 'results': results, 'error': err, 'duration_ms': dur,
        })

        # 清理旧日志（保留最近 5000 条）
    try:
        await db(
            "DELETE FROM hook_logs WHERE id < (SELECT MAX(id) - 5000 FROM hook_logs)"
        )
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- CRUD
async def list_hooks() -> List[dict]:
    db = _require_db()
    return await db("SELECT * FROM hooks ORDER BY priority ASC, id ASC") or []


async def get_hook(hook_id: str) -> Optional[dict]:
    db = _require_db()
    rows = await db("SELECT * FROM hooks WHERE hook_id = ?", (hook_id,))
    return rows[0] if rows else None


async def create_hook(name: str, events: str, condition: str, actions: str,
                      description: str = '', priority: int = 100,
                      is_enabled: bool = True, created_by: str = '') -> dict:
    db = _require_db()
    check = validate_hook(events, condition, actions)
    if not check['ok']:
        raise HookError('; '.join(check['errors']))
    hook_id = 'hook_' + uuid.uuid4().hex[:12]
    await db(
        """INSERT INTO hooks
           (hook_id, name, description, events, condition, actions, is_enabled,
            priority, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
        (hook_id, (name or '未命名钩子')[:100], (description or '')[:500],
         ','.join(check['events']), (condition or '').strip(), (actions or '').strip(),
         1 if is_enabled else 0, int(priority), created_by)
    )
    return {'hook_id': hook_id, 'warnings': check['warnings']}


async def update_hook(hook_id: str, **fields) -> dict:
    db = _require_db()
    cur = await get_hook(hook_id)
    if not cur:
        raise HookError('钩子不存在')

    events = fields.get('events', cur['events'])
    condition = fields.get('condition', cur['condition'])
    actions = fields.get('actions', cur['actions'])
    check = validate_hook(events, condition, actions)
    if not check['ok']:
        raise HookError('; '.join(check['errors']))

    await db(
        """UPDATE hooks SET name = ?, description = ?, events = ?, condition = ?,
           actions = ?, is_enabled = ?, priority = ?, updated_at = CURRENT_TIMESTAMP
           WHERE hook_id = ?""",
        ((fields.get('name', cur['name']) or '未命名钩子')[:100],
         (fields.get('description', cur['description']) or '')[:500],
         ','.join(check['events']), (condition or '').strip(), (actions or '').strip(),
         1 if int(fields.get('is_enabled', cur['is_enabled'])) else 0,
         int(fields.get('priority', cur['priority'])), hook_id)
    )
    return {'hook_id': hook_id, 'warnings': check['warnings']}


async def delete_hook(hook_id: str) -> bool:
    db = _require_db()
    n = await db("DELETE FROM hooks WHERE hook_id = ?", (hook_id,))
    await db("DELETE FROM hook_logs WHERE hook_id = ?", (hook_id,))
    return bool(n)


async def test_hook(events: str, condition: str, actions: str,
                    trigger_uid: str = '', target_uid: str = '',
                    dry_run: bool = True) -> dict:
    """在后台测试钩子。dry_run=True 只做条件求值与动作解析，不产生副作用。"""
    check = validate_hook(events, condition, actions)
    evs = check['events'] or ['USER_LOGIN']
    event_name = evs[0]

    if trigger_uid or target_uid:
        ctx = await build_context(event_name, {
            'trigger_user': trigger_uid or None,
            'target_user': target_uid or None,
            'amount': 1, 'model': 'test-model', 'tokens': 100, 'cost': 0.01,
            'content': '测试内容', 'reason': '测试', 'client_ip': '127.0.0.1',
        })
    else:
        ctx = _dry_context(event_name)

    out = {'validate': check, 'event': event_name, 'matched': None,
           'results': [], 'error': '', 'dry_run': dry_run}
    if not check['ok']:
        out['error'] = '; '.join(check['errors'])
        return out
    try:
        out['matched'] = evaluate_condition(condition, ctx)
        if out['matched']:
            if dry_run:
                plan = _plan_actions(actions, ctx)
                out['results'] = [
                    f"[dry-run] {n}(" + ', '.join(
                        [_repr_arg(a) for a in a_] + [f'{k}={_repr_arg(v)}' for k, v in kw.items()]
                    ) + ')'
                    for n, a_, kw in plan
                ]
            else:
                out['results'] = await run_actions(actions, ctx)
    except HookError as e:
        out['error'] = str(e)
    except Exception as e:
        out['error'] = f'内部错误: {e}'
    return out


def _repr_arg(v: Any) -> str:
    if isinstance(v, UserRef):
        return f'<用户 {v.user_name or v.uid}>'
    if isinstance(v, str):
        return '"' + v[:80] + '"'
    return str(v)


def hook_meta() -> dict:
    """给前端的元信息：事件目录、静态方法、动态常量、用户成员"""
    return {
        'events': [
            {'name': k, 'desc': v['desc'], 'vars': v['vars']}
            for k, v in EVENT_CATALOG.items()
        ],
        'static_members': [
            {'name': k, 'sig': v['sig'], 'desc': v['desc']}
            for k, v in STATIC_MEMBERS.items()
        ],
        'dynamic_members': [{'name': k, 'desc': v} for k, v in DYNAMIC_MEMBERS.items()],
        'user_members': sorted(USER_FIELD_MAP.keys()),
        'pure_functions': sorted(_safe_pure_funcs().keys()),
    }


async def list_hook_logs(hook_id: str = '', limit: int = 100) -> List[dict]:
    db = _require_db()
    limit = max(1, min(int(limit), 500))
    if hook_id:
        return await db(
            "SELECT * FROM hook_logs WHERE hook_id = ? ORDER BY id DESC LIMIT ?",
            (hook_id, limit)
        ) or []
    return await db("SELECT * FROM hook_logs ORDER BY id DESC LIMIT ?", (limit,)) or []
