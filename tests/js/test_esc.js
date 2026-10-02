/**
 * 全局 HTML 转义函数 esc() 回归测试（纯 node，无第三方依赖）
 *
 *   运行：node tests/js/test_esc.js
 *
 * 背景：dashboard 管理端表格曾把 用户名/UID/充值备注/模型名/接口 error 文案直接拼进
 * innerHTML 与 HTML 属性，存在存储型 XSS。现统一经 templates/dashboard.html 顶部的 esc()
 * 转义后再拼接，本测试锁定其中和行为（含防属性逃逸的引号编码）。
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const TPL = path.join(ROOT, 'templates', 'dashboard.html');
const src = fs.readFileSync(TPL, 'utf8');
const m = src.match(/function esc\(s\) \{[\s\S]*?\n    \}/);
if (!m) { console.error('FAIL: 未找到 esc 定义'); process.exit(1); }
// 严格模式下 eval 内的函数声明不会泄漏到外层，需显式取出引用
const esc = eval(m[0] + '\n; esc;');

let pass = 0, fail = 0;
function eq(name, got, want) {
  if (got === want) { pass++; console.log('  ok  ', name, '=>', got); }
  else { fail++; console.log('  FAIL', name, '=> got', JSON.stringify(got), 'want', JSON.stringify(want)); }
}

eq('尖括号标签', esc('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
eq('双引号（防属性逃逸）', esc('a" onload="alert(1)'), 'a&quot; onload=&quot;alert(1)');
eq('单引号', esc("it's"), 'it&#39;s');
eq('& 符号', esc('a & b'), 'a &amp; b');
eq('null', esc(null), '');
eq('undefined', esc(undefined), '');
eq('数字 0 不被吞掉', esc(0), '0');
eq('正常中文不被改动', esc('张三'), '张三');

// data-args="'...'" 场景：值里的双引号必须编码，否则会提前闭合 HTML 属性
const attr = "'" + esc('uid" onmouseover="alert(1)') + "'";
eq('data-args 属性不含裸双引号', /"/.test(attr), false);

// 接口 error 文案（进 toast / 空态提示）
eq('错误文案', esc('余额不足: <script>'), '余额不足: &lt;script&gt;');

console.log(`\n${fail ? 'FAIL' : 'ALL OK'}  pass=${pass} fail=${fail}`);
process.exit(fail ? 1 : 0);
