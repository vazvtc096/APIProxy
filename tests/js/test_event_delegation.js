/**
 * data-action 事件委托回归测试（纯 node，无第三方依赖）
 *
 *   运行：node tests/js/test_event_delegation.js
 *
 * 背景：middleware/security_middleware.py 会把 _EVENT_DELEGATION_JS 注入到每个 HTML 响应，
 * 而 templates/_sidebar.html 里曾存在第二套实现，两者都绑在 document 上，导致一次点击
 * 被执行两遍；且注入版本不做单引号剥离，data-args="'${id}'" 会带上传引号。现以注入版本为
 * 唯一权威实现（window.__actionDelegationInstalled 幂等标记），本测试锁定其参数解析与调用顺序。
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const MW = path.join(ROOT, 'middleware', 'security_middleware.py');
const src = fs.readFileSync(MW, 'utf8');
const m = src.match(/_EVENT_DELEGATION_JS = """<script>([\s\S]*?)<\/script>"""/);
if (!m) { console.error('FAIL: 未找到 _EVENT_DELEGATION_JS'); process.exit(1); }
const js = m[1].replace(/\\\\u0001/g, '\\u0001');

// ---- 最小 DOM 桩 ----
const listeners = {};
global.window = global;
global.document = {
  addEventListener: (t, fn) => { (listeners[t] = listeners[t] || []).push(fn); }
};
function mkEl(attrs, tag = 'BUTTON') {
  const a = new Map(Object.entries(attrs));
  const self = {
    tagName: tag,
    getAttribute: k => (a.has(k) ? a.get(k) : null),
    hasAttribute: k => a.has(k),
    closest(sel) {
      const mm = /^\[([a-z0-9-]+)\]$/i.exec(sel);
      if (mm) return a.has(mm[1]) ? self : null;
      return null; // 本桩中所有元素都不在 form 内
    }
  };
  return self;
}
function fire(type, el, ev = { type }) {
  const e = { type, target: el, preventDefault() { e.__prevented = true; }, stopPropagation() {}, ...ev };
  (listeners[type] || []).forEach(fn => fn(e));
  return e;
}

const calls = [];
function reg(name, fn) { global[name] = function (...args) { calls.push([name, ...args]); return fn ? fn(...args) : undefined; }; }

eval(js);

let pass = 0, fail = 0;
function eq(name, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { pass++; console.log('  ok  ', name, '=>', g); }
  else { fail++; console.log('  FAIL', name, '=> got', g, 'want', w); }
}

// 1) 幂等：重复注入不重复注册（这是"点击只执行一次"的前提）
const n1 = (listeners['click'] || []).length;
eval(js);
eq('幂等注册（第二次不重复绑定）', (listeners['click'] || []).length, n1);

// 2) 历史写法 data-args="'${id}'" 必须剥离字面单引号
reg('deleteApiKey');
fire('click', mkEl({ 'data-action': 'deleteApiKey', 'data-args': "'sk-abc'" }));
eq('单引号剥离', calls.pop(), ['deleteApiKey', 'sk-abc']);

// 3) \u0001 多参数（非布尔保持字符串，避免 "0123" 之类 ID 被误转成数字）
reg('setOverdraft');
fire('click', mkEl({ 'data-action': 'setOverdraft', 'data-args': "'uid1'\u0001'张三'\u000150" }));
eq('\\u0001 分隔多参数', calls.pop(), ['setOverdraft', 'uid1', '张三', '50']);

// 4) 布尔还原：否则 "false" 是 truthy，toggleHook 的 !enabled 永远为 false（钩子无法启用）
reg('toggleHook');
fire('click', mkEl({ 'data-action': 'toggleHook', 'data-args': "'hk1'\u0001false" }));
eq('布尔还原 false', calls.pop(), ['toggleHook', 'hk1', false]);
fire('click', mkEl({ 'data-action': 'toggleHook', 'data-args': "'hk1'\u0001true" }));
eq('布尔还原 true', calls.pop(), ['toggleHook', 'hk1', true]);

// 5) JSON 参数（数字不做字符串化）
reg('switchChartPeriod');
fire('click', mkEl({ 'data-action': 'switchChartPeriod', 'data-args': '30' }));
eq('JSON 数字参数', calls.pop(), ['switchChartPeriod', 30]);

// 6) 参数顺序：data-arg-event 最前（既有模板 startLongPress(event, msgId, ...) 依赖此顺序）
reg('startLongPress');
fire('touchstart', mkEl({ 'data-on-touchstart': 'startLongPress', 'data-arg-event': '', 'data-args': 'm1\u0001hello\u0001true' }));
const c6 = calls.pop();
eq('event 在最前', c6[0], 'startLongPress');
eq('event 对象传参', c6[1] && c6[1].type, 'touchstart');
eq('event 后接 args', [c6[2], c6[3], c6[4]], ['m1', 'hello', true]);

// 7) data-arg-this 排在 args 之后（toggleFavorite(postId, btn) 依赖此顺序）
reg('toggleFavorite');
const el7 = mkEl({ 'data-action': 'toggleFavorite', 'data-args': 'p1', 'data-arg-this': '' });
fire('click', el7);
const c7 = calls.pop();
eq('arg-this 排在 args 之后', [c7[0], c7[1], c7[2] === el7], ['toggleFavorite', 'p1', true]);

// 8) data-then（含参数解析）
reg('setActiveTab');
reg('loadOverviewUsage');
fire('click', mkEl({ 'data-action': 'setActiveTab', 'data-arg-this': '', 'data-then': 'loadOverviewUsage', 'data-then-args': '7' }));
const then = calls[calls.length - 1];
eq('data-then 参数', [then[0], then[1]], ['loadOverviewUsage', 7]);

// 9) data-nav 跳转
let nav = null;
Object.defineProperty(global, 'location', { value: { set href(v) { nav = v; } }, writable: true });
fire('click', mkEl({ 'data-nav': '/dashboard/apikeys' }));
eq('data-nav 跳转', nav, '/dashboard/apikeys');

// 10) 按钮上的 data-action 应阻止默认行为，避免意外提交/跳转
const e10 = fire('click', mkEl({ 'data-action': 'setActiveTab', 'data-arg-this': '' }));
eq('按钮阻止默认行为', e10.__prevented, true);

// 11) 不存在的函数只告警不抛异常
fire('click', mkEl({ 'data-action': 'doesNotExist', 'data-args': '1' }));
eq('未知 action 不抛异常', true, true);

// 12) 通知项点击链路：data-args="<id>\u0001<link>" 无引号包裹，openNotif(id, link) 顺序正确
//     （修复前通知项只写 data-nav，永远不标记已读；现统一走 openNotif → 先标记已读再跳转）
reg('openNotif');
fire('click', mkEl({ 'data-action': 'openNotif', 'data-args': 'nid_8f3a\u0001/admin/announcements/12' }));
eq('通知项 openNotif 参数顺序', calls.pop(), ['openNotif', 'nid_8f3a', '/admin/announcements/12']);
// 无 link 的通知：link 为空字符串，openNotif 仅刷新不跳转
fire('click', mkEl({ 'data-action': 'openNotif', 'data-args': 'nid_empty\u0001' }));
eq('通知项 无 link 时 openNotif 仍收空串', calls.pop(), ['openNotif', 'nid_empty', '']);

console.log(`\n${fail ? 'FAIL' : 'ALL OK'}  pass=${pass} fail=${fail}`);
process.exit(fail ? 1 : 0);
