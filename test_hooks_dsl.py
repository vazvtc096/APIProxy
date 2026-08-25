"""钩子 DSL 引擎单元测试（不依赖 Quart / 数据库）

运行: python test_hooks_dsl.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from APIProxy import hooks as H  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond, extra=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  [PASS] {name}')
    else:
        FAIL += 1
        print(f'  [FAIL] {name} {extra}')


def ctx_of(**over):
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


print('=' * 60)
print('1. 条件求值')
print('=' * 60)
c = ctx_of()
cases_true = [
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
for expr in cases_true:
    try:
        r = H.evaluate_condition(expr, c)
        check(f'真: {expr}', r is True, f'-> {r}')
    except Exception as e:
        check(f'真: {expr}', False, f'异常 {e}')

cases_false = [
    'TRIGGER_USER.loginCount > 5',
    'TRIGGER_USER.isAdmin == 1',
    'TRIGGER_USER.userName == "admin"',
    'EVENT_NAME == "USER_REGISTER"',
]
for expr in cases_false:
    try:
        r = H.evaluate_condition(expr, c)
        check(f'假: {expr}', r is False, f'-> {r}')
    except Exception as e:
        check(f'假: {expr}', False, f'异常 {e}')

check('空条件恒真', H.evaluate_condition('', c) is True)
check('空白条件恒真', H.evaluate_condition('   ', c) is True)

print()
print('=' * 60)
print('2. 沙箱逃逸必须被拦截')
print('=' * 60)
attacks = [
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
for expr in attacks:
    try:
        r = H.evaluate_condition(expr, c)
        check(f'拦截: {expr[:45]}', False, f'未拦截，返回 {r!r}')
    except H.HookError as e:
        check(f'拦截: {expr[:45]}', True)
    except Exception as e:
        # 其他异常也算拦截（不会执行恶意代码），但标注类型
        check(f'拦截: {expr[:45]}', True, f'({type(e).__name__})')

print()
print('=' * 60)
print('3. 动作解析（dry-run，不产生副作用）')
print('=' * 60)
ok_actions = [
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
for a in ok_actions:
    try:
        plan = H._plan_actions(a, c)
        check(f'解析: {a[:52]}', len(plan) >= 1, f'-> {len(plan)} 个动作')
    except Exception as e:
        check(f'解析: {a[:52]}', False, f'异常 {e}')

# 多动作切分正确性
plan = H._plan_actions('send_message(TRIGGER_USER, "a;b"); add_balence(TRIGGER_USER, 2); log("c")', c)
check('分号切分 = 3 个动作', len(plan) == 3, f'-> {len(plan)}')
check('第一个动作参数含分号字符串', plan[0][1][1] == 'a;b', f'-> {plan[0][1][1]!r}')

bad_actions = [
    'unknown_action(TRIGGER_USER)',
    '1 + 1',
    'TRIGGER_USER.balence',
    'send_message(TRIGGER_USER, "未闭合',
    'send_message(TRIGGER_USER, "x"',
    '',
    '__import__("os").system("x")',
    'send_message(TRIGGER_USER, "a"); ' * 25,  # 超过 20 个动作
]
for a in bad_actions:
    try:
        H._plan_actions(a, c)
        check(f'拒绝: {a[:45]!r}', False, '未拒绝')
    except H.HookError:
        check(f'拒绝: {a[:45]!r}', True)
    except Exception as e:
        check(f'拒绝: {a[:45]!r}', True, f'({type(e).__name__})')

print()
print('=' * 60)
print('4. 格式化 %s 语义')
print('=' * 60)
check('单参数', H._apply_format('你好 %s', ('Polan',)) == '你好 Polan')
check('多参数', H._apply_format('%s 有 %s 元', ('Polan', 3.5)) == 'Polan 有 3.5 元')
check('无参数', H._apply_format('纯文本', ()) == '纯文本')
check('参数多于占位符不炸', isinstance(H._apply_format('只有一个 %s', ('a', 'b')), str))
check('占位符多于参数不炸', isinstance(H._apply_format('%s %s %s', ('a',)), str))
check('UserRef 自动转字符串', 'Polan' in H._apply_format('%s', (c['TRIGGER_USER'],)))

print()
print('=' * 60)
print('5. validate_hook 静态校验')
print('=' * 60)
v = H.validate_hook('USER_LOGIN', 'TRIGGER_USER.loginCount <= 1',
                    'send_message(TRIGGER_USER, "你好 %s", TRIGGER_USER.userName)')
check('合法钩子通过', v['ok'] is True, str(v))
check('事件解析正确', v['events'] == ['USER_LOGIN'], str(v['events']))

v = H.validate_hook('USER_LOGIN,USER_REGISTER', '', 'log("x")')
check('多事件解析', v['ok'] and v['events'] == ['USER_LOGIN', 'USER_REGISTER'], str(v))

v = H.validate_hook('', '', 'log("x")')
check('缺事件被拒', v['ok'] is False and any('事件' in e for e in v['errors']), str(v))

v = H.validate_hook('USER_LOGIN', '', '')
check('缺动作被拒', v['ok'] is False, str(v))

v = H.validate_hook('USER_LOGIN', 'TRIGGER_USER.badField == 1', 'log("x")')
check('未知成员被拒', v['ok'] is False, str(v))

v = H.validate_hook('NOT_A_REAL_EVENT', '', 'log("x")')
check('未知事件为警告非错误', v['ok'] is True and len(v['warnings']) == 1, str(v))

v = H.validate_hook('USER_LOGIN', '__import__("os")', 'log("x")')
check('条件中的攻击被拒', v['ok'] is False, str(v))

print()
print('=' * 60)
print('6. 数值/字符串宽松比较（DB TEXT 存数字场景）')
print('=' * 60)
c2 = ctx_of(balence='3.5', login_count='1')
check('TEXT 余额比较', H.evaluate_condition('TRIGGER_USER.balence > 3', c2) is True)
check('TEXT 次数比较', H.evaluate_condition('TRIGGER_USER.loginCount <= 1', c2) is True)
c3 = ctx_of(login_count=None)
check('NULL 计数缺省为 0', H.evaluate_condition('TRIGGER_USER.loginCount <= 1', c3) is True)

print()
print('=' * 60)
print('7. test_hook dry-run（异步，不落库）')
print('=' * 60)


async def _t():
    r = await H.test_hook('USER_LOGIN', 'TRIGGER_USER.loginCount <= 1',
                          'send_message(TRIGGER_USER, "你好 %s", TRIGGER_USER.userName); add_balence(TRIGGER_USER, 1)',
                          dry_run=True)
    check('dry-run 校验通过', r['validate']['ok'] is True, str(r))
    check('dry-run 条件命中', r['matched'] is True, str(r))
    check('dry-run 返回 2 个动作预览', len(r['results']) == 2, str(r['results']))
    print('       预览:', r['results'])

    r2 = await H.test_hook('USER_LOGIN', 'TRIGGER_USER.loginCount > 99', 'log("x")', dry_run=True)
    check('dry-run 条件未命中', r2['matched'] is False, str(r2))


asyncio.run(_t())

print()
print('=' * 60)
print('8. hook_meta 元信息')
print('=' * 60)
m = H.hook_meta()
check('事件目录非空', len(m['events']) >= 20, str(len(m['events'])))
check('静态成员非空', len(m['static_members']) >= 10, str(len(m['static_members'])))
check('动态成员含 TRIGGER_USER',
      any(d['name'] == 'TRIGGER_USER' for d in m['dynamic_members']))
check('动态成员含 TARGET_USER',
      any(d['name'] == 'TARGET_USER' for d in m['dynamic_members']))
check('动态成员含 EVENT_NAME',
      any(d['name'] == 'EVENT_NAME' for d in m['dynamic_members']))
check('用户成员含 loginCount', 'loginCount' in m['user_members'])
check('用户成员含 userName', 'userName' in m['user_members'])

print()
print('=' * 60)
print(f'结果: {PASS} 通过, {FAIL} 失败')
print('=' * 60)
sys.exit(1 if FAIL else 0)
