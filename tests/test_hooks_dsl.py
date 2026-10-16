"""钩子 DSL 引擎单元测试（不依赖 Quart / 数据库）。

原为仓库根目录下的脚本式自检 `test_hooks_dsl.py`（自定义 check() + sys.exit），
因 pytest.ini 的 testpaths=tests 而从不进入 CI —— 即整个 DSL 引擎唯一的逃逸测试
长期处于无人跑的状态。此处改写为 pytest 原生用例，纳入常规回归。

运行: python -m pytest tests/test_hooks_dsl.py -q
"""
import asyncio
import sys

import pytest

from APIProxy import hooks as H


def _ctx(**over):
    base = {
        'uid': 'u0001', 'user_name': 'Polan', 'email': 'p@e.com', 'balence': 3.5,
        'is_admin': 0, 'is_banned': 0, 'login_count': 1, 'total_spent': 12.5,
        'created_at': '2026-01-01 00:00:00', 'max_sessions': 1, 'max_overdraft': 0.0,
        'allow_overdraft': 0, 'ban_reason': '', 'last_login_ip': '1.2.3.4',
        'last_login_time': '', 'last_device_type': 'desktop', 'last_device_os': '',
        'last_active_time': '',
    }
    base.update(over)
    return {
        'EVENT_NAME': 'USER_LOGIN',
        'EVENT_TIME': '2026-08-17 12:00:00',
        'TRIGGER_USER': H.UserRef(base),
        'TARGET_USER': H.UserRef(None),
        'CLIENT_IP': '1.2.3.4',
        'AMOUNT': 10.0, 'MODEL': 'deepseek-chat', 'TOKENS': 500.0, 'COST': 0.02,
        'CONTENT': 'hello', 'POST_ID': 'p1', 'REASON': '',
    }


CTX = _ctx()


# ============================================================================
# 1. 条件求值
# ============================================================================

CASES_TRUE = [
    'TRIGGER_USER.loginCount <= 1',
    'TRIGGER_USER.userName == "Polan"',
    'TRIGGER_USER.balence > 3 and TRIGGER_USER.isAdmin == 0',
    'EVENT_NAME == "USER_LOGIN"',
    'TRIGGER_USER.loginCount <= 1 or TRIGGER_USER.balence > 100',
    'not TRIGGER_USER.isBanned',
    'len(TRIGGER_USER.userName) == 5',
    '"Pol" in TRIGGER_USER.userName',
    'TRIGGER_USER.balence * 2 >= 7',
    'contains(TRIGGER_USER.email, "@")',
    'AMOUNT >= 10 and TOKENS < 1000',
    '(TRIGGER_USER.loginCount == 1) == True',
    'TRIGGER_USER.userName in ["Polan", "test"]',
    'round(TRIGGER_USER.balence) == 4',
    'lower(TRIGGER_USER.userName) == "polan"',
    'TRIGGER_USER.loginCount if TRIGGER_USER.isAdmin == 0 else 0',
    'not TARGET_USER',
]

CASES_FALSE = [
    'TRIGGER_USER.loginCount > 5',
    'TRIGGER_USER.isAdmin == 1',
    'TRIGGER_USER.userName == "admin"',
    'EVENT_NAME == "USER_REGISTER"',
]


@pytest.mark.parametrize("expr", CASES_TRUE)
def test_condition_true(expr):
    assert H.evaluate_condition(expr, CTX) is True


@pytest.mark.parametrize("expr", CASES_FALSE)
def test_condition_false(expr):
    assert H.evaluate_condition(expr, CTX) is False


@pytest.mark.parametrize("expr", ["", "   "])
def test_empty_condition_is_true(expr):
    assert H.evaluate_condition(expr, CTX) is True


# ============================================================================
# 2. 沙箱逃逸必须被拦截（任何异常都算拦截，关键是「不执行恶意代码」）
# ============================================================================

ATTACKS = [
    '__import__("os").system("calc")',
    'open("/etc/passwd").read()',
    'eval("1+1")',
    'exec("x=1")',
    '().__class__.__bases__[0].__subclasses__()',
    'TRIGGER_USER.__class__',
    'TRIGGER_USER._data',
    '[x for x in range(10)]',
    'lambda: 1',
    'globals()',
    'locals()',
    'getattr(TRIGGER_USER, "_data")',
    'TRIGGER_USER.__dict__',
    '2 ** 999999999',
    '"a" * 999999999',
    'unknown_name > 1',
    'TRIGGER_USER.notAField == 1',
    'import os',
    'x := 5',
    'print("hi")',
    'compile("1","","eval")',
    'vars()',
    'setattr(TRIGGER_USER, "balence", 999)',
    'TRIGGER_USER.userName.__class__.__mro__',
    'f"{TRIGGER_USER}"' if sys.version_info >= (3, 12) else 'type(1)',
]


@pytest.mark.parametrize("expr", ATTACKS)
def test_sandbox_escape_is_blocked(expr):
    with pytest.raises(Exception):
        H.evaluate_condition(expr, CTX)


def test_sandbox_raises_hooK_error_not_silent_none():
    """逃逸必须显式抛 HookError，而不是静默返回 None/False。"""
    with pytest.raises(H.HookError):
        H.evaluate_condition('__import__("os").system("calc")', CTX)


# ============================================================================
# 3. 动作解析（dry-run，不产生副作用）
# ============================================================================

OK_ACTIONS = [
    'send_message(TRIGGER_USER, "你好 %s", TRIGGER_USER.userName)',
    'add_balence(TRIGGER_USER, 1.5)',
    'send_message(TRIGGER_USER, "欢迎"); add_balence(TRIGGER_USER, 1)',
    'send_message(TRIGGER_USER, "a;b 分号在字符串里不切分")',
    'add_balence(TRIGGER_USER, 1, remark="新人礼包")',
    'ban_user(TRIGGER_USER, "刷接口", 30)',
    'log("事件 %s 触发", EVENT_NAME)',
    'notify_admin("用户 %s 登录", TRIGGER_USER.userName)',
    'send_message(TRIGGER_USER, "余额 %s", TRIGGER_USER.balence); log("done")',
    'send(TRIGGER_USER, "别名可用")',
    'block_ip(CLIENT_IP, "hook", 10)',
    'send_announcement("系统维护", "今晚 22:00 维护")',
]

BAD_ACTIONS = [
    'unknown_action(TRIGGER_USER)',
    '1 + 1',
    'TRIGGER_USER.balence',
    'send_message(TRIGGER_USER, "未闭合',
    'send_message(TRIGGER_USER, "x"',
    '',
    '__import__("os").system("x")',
    'send_message(TRIGGER_USER, "a"); ' * 25,  # 超过 20 个动作上限
]


@pytest.mark.parametrize("action", OK_ACTIONS)
def test_action_plan_ok(action):
    plan = H._plan_actions(action, CTX)
    assert len(plan) >= 1


@pytest.mark.parametrize("action", BAD_ACTIONS)
def test_action_plan_rejected(action):
    with pytest.raises(Exception):
        H._plan_actions(action, CTX)


def test_action_split_by_semicolon():
    plan = H._plan_actions(
        'send_message(TRIGGER_USER, "a;b"); add_balence(TRIGGER_USER, 2); log("c")', CTX)
    assert len(plan) == 3
    assert plan[0][1][1] == 'a;b'


# ============================================================================
# 4. 格式化 %s 语义
# ============================================================================

@pytest.mark.parametrize("tpl,args,expected", [
    ('你好 %s', ('Polan',), '你好 Polan'),
    ('%s 有 %s 元', ('Polan', 3.5), 'Polan 有 3.5 元'),
    ('纯文本', (), '纯文本'),
])
def test_apply_format(tpl, args, expected):
    assert H._apply_format(tpl, args) == expected


@pytest.mark.parametrize("tpl,args", [
    ('只有一个 %s', ('a', 'b')),   # 参数多于占位符
    ('%s %s %s', ('a',)),          # 占位符多于参数
])
def test_apply_format_tolerates_arity_mismatch(tpl, args):
    assert isinstance(H._apply_format(tpl, args), str)


def test_apply_format_userref_str():
    assert 'Polan' in H._apply_format('%s', (CTX['TRIGGER_USER'],))


# ============================================================================
# 5. validate_hook 静态校验
# ============================================================================

def test_validate_hook_ok():
    v = H.validate_hook(
        'USER_LOGIN', 'TRIGGER_USER.loginCount <= 1',
        'send_message(TRIGGER_USER, "你好 %s", TRIGGER_USER.userName)')
    assert v['ok'] is True
    assert v['events'] == ['USER_LOGIN']


def test_validate_hook_multi_events():
    v = H.validate_hook('USER_LOGIN,USER_REGISTER', '', 'log("x")')
    assert v['ok'] is True
    assert v['events'] == ['USER_LOGIN', 'USER_REGISTER']


def test_validate_hook_missing_event_rejected():
    v = H.validate_hook('', '', 'log("x")')
    assert v['ok'] is False
    assert any('事件' in e for e in v['errors'])


def test_validate_hook_missing_action_rejected():
    v = H.validate_hook('USER_LOGIN', '', '')
    assert v['ok'] is False


def test_validate_hook_unknown_member_rejected():
    v = H.validate_hook('USER_LOGIN', 'TRIGGER_USER.badField == 1', 'log("x")')
    assert v['ok'] is False


def test_validate_hook_unknown_event_warns_not_errors():
    v = H.validate_hook('NOT_A_REAL_EVENT', '', 'log("x")')
    assert v['ok'] is True
    assert len(v['warnings']) == 1


def test_validate_hook_attack_in_condition_rejected():
    v = H.validate_hook('USER_LOGIN', '__import__("os")', 'log("x")')
    assert v['ok'] is False


# ============================================================================
# 6. 数值/字符串宽松比较（DB TEXT 存数字场景）
# ============================================================================

def test_text_numeric_comparison():
    c2 = _ctx(balence='3.5', login_count='1')
    assert H.evaluate_condition('TRIGGER_USER.balence > 3', c2) is True
    assert H.evaluate_condition('TRIGGER_USER.loginCount <= 1', c2) is True


def test_null_count_defaults_to_zero():
    c3 = _ctx(login_count=None)
    assert H.evaluate_condition('TRIGGER_USER.loginCount <= 1', c3) is True


# ============================================================================
# 7. test_hook dry-run（异步，不落库）
# ============================================================================

def test_test_hook_dry_run_matched():
    async def _run():
        return await H.test_hook(
            'USER_LOGIN', 'TRIGGER_USER.loginCount <= 1',
            'send_message(TRIGGER_USER, "你好 %s", TRIGGER_USER.userName); add_balence(TRIGGER_USER, 1)',
            dry_run=True)

    r = asyncio.run(_run())
    assert r['validate']['ok'] is True
    assert r['matched'] is True
    assert len(r['results']) == 2


def test_test_hook_dry_run_not_matched():
    async def _run():
        return await H.test_hook(
            'USER_LOGIN', 'TRIGGER_USER.loginCount > 99', 'log("x")', dry_run=True)

    r = asyncio.run(_run())
    assert r['matched'] is False


# ============================================================================
# 8. hook_meta 元信息
# ============================================================================

def test_hook_meta_catalog():
    m = H.hook_meta()
    assert len(m['events']) >= 20
    assert len(m['static_members']) >= 10
    dynamic_names = {d['name'] for d in m['dynamic_members']}
    assert {'TRIGGER_USER', 'TARGET_USER', 'EVENT_NAME'} <= dynamic_names
    assert 'loginCount' in m['user_members']
    assert 'userName' in m['user_members']
