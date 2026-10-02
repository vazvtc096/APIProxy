# 豁免密钥（Exemption Key）功能集成指南

允许用户申请临时豁免人机验证，管理员审核通过后生成 `ex-` 开头的密钥，凭密钥可在 10 分钟内、从申请 IP 一次性通过注册的人机验证。

## 密钥规格

- 格式：`ex-` + 48 位十六进制（24 字节熵），与 API Key 同等安全规格
- 示例：`ex-a72f34c9...（共51字符）`

## 安全特性

| 特性 | 说明 |
|------|------|
| 一次性使用 | 验证通过后立即标记为 used，无法重复使用 |
| IP 绑定 | 只能在申请时的 IP 上使用，防止密钥被拦截后别处用 |
| 10 分钟硬过期 | 批准后 10 分钟未使用自动失效 |
| 申请速率限制 | 每 IP 每分钟最多申请 1 次 |
| 防重复申请 | 同一 IP 有 pending 申请时不能重复提交 |
| 哈希存储 | 数据库只存 SHA256 哈希，不存明文密钥 |
| 全流程审计 | 申请、批准、拒绝、使用全部记录日志 |

---

## 第一步：复制文件

```bash
# 核心模块（放到项目根目录，和 apikey.py 同级）
cp exemption.py /path/to/APIProxy/exemption.py

# 路由模块（放到 routes/ 目录）
cp exemption_routes.py /path/to/APIProxy/routes/exemption_routes.py
```

---

## 第二步：数据库初始化

在 `init_db.py` 或应用启动代码中添加：

```python
from .exemption import init_exemption_table

# 应用启动时调用
init_exemption_table()
```

会自动创建 `exemption_requests` 表及索引。

---

## 第三步：注册路由

在 `app.py` 或 `__main__.py` 中注册蓝图：

```python
from .routes.exemption_routes import exemption_bp

app.register_blueprint(exemption_bp)
```

---

## 第四步：注册接口集成（routes/auth.py）

在 `register()` 函数中，把原来的人机验证逻辑改成：

```python
from ..exemption import verify_exemption_key

# 读取请求参数
exemption_key = data.get('exemption_key', '').strip()

# 在验证方式分支处：
if exemption_key:
    # 用户携带了豁免密钥，验证通过则跳过人机验证
    ok, msg = verify_exemption_key(exemption_key, _get_client_ip(), username=owner)
    if not ok:
        return jsonify({'error': msg}), 400
    # 验证通过，email 置空（豁免注册通常不需要邮箱）
    email = ''
elif SMTP_CONFIGURED and email:
    # 提供了邮箱：走邮箱验证码（原有逻辑）
    ...
else:
    # 未提供邮箱：走 Turnstile / 滑块验证码（原有逻辑）
    ...
```

---

## 第五步：前端页面

### 5.1 申请豁免页面

用户在注册页点击"申请豁免"，填写理由提交。

```javascript
async function requestExemption(reason) {
    const resp = await fetch('/api/exemption/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason }),
    });
    const data = await resp.json();
    if (resp.ok) {
        // 提交成功，保存 request_id 用于轮询状态
        localStorage.setItem('exemption_request_id', data.request_id);
        alert('申请已提交，请等待管理员审核');
        // 开始轮询状态
        pollExemptionStatus(data.request_id);
    } else {
        alert(data.error);
    }
}

// 轮询申请状态（每5秒查一次）
async function pollExemptionStatus(requestId) {
    const interval = setInterval(async () => {
        const resp = await fetch(`/api/exemption/status/${requestId}`);
        if (resp.ok) {
            const data = await resp.json();
            if (data.status === 'approved') {
                clearInterval(interval);
                alert('申请已批准！请联系管理员获取豁免密钥');
                // 注意：密钥只在管理员批准时显示一次，前端拿不到
                // 需要管理员通过其他渠道（如私聊）发给用户
            } else if (data.status === 'rejected') {
                clearInterval(interval);
                alert('申请被拒绝：' + (data.reject_reason || ''));
            }
            // pending 状态继续轮询
        }
    }, 5000);
}
```

### 5.2 注册页使用豁免密钥

用户拿到管理员发的密钥后，在注册页填写：

```html
<!-- 豁免密钥输入框（可选，默认隐藏） -->
<div id="exemption-group" style="display:none; margin: 16px 0;">
    <label>豁免密钥（如有）</label>
    <input type="text" id="exemptionKey" placeholder="ex-xxxxxxxx..." maxlength="51">
    <div style="font-size:12px;color:#999;margin-top:4px;">
        填写后可跳过人机验证，10分钟内有效，只能使用一次
    </div>
</div>
```

提交时携带：
```javascript
const exemptionKey = document.getElementById('exemptionKey').value.trim();
if (exemptionKey) {
    payload.exemption_key = exemptionKey;
}
```

---

## 第六步：管理员审核

### 6.1 待审核列表

```
GET /api/admin/exemption/pending
```

返回：
```json
{
  "pending": [
    {
      "id": 1,
      "requester_ip": "1.2.3.4",
      "requester_ua": "Mozilla/5.0...",
      "device_fingerprint": "xxx",
      "reason": "我是开发者，需要批量测试",
      "created_at": 1756300000.0
    }
  ],
  "count": 1
}
```

### 6.2 批准

```
POST /api/admin/exemption/approve/1
```

返回：
```json
{
  "message": "申请已批准",
  "request_id": 1,
  "exemption_key": "ex-a72f34c9...",
  "validity_seconds": 600,
  "note": "此密钥仅显示一次，请立即复制发给申请人。"
}
```

> ⚠️ **密钥只在批准时返回一次**，管理员需要立即复制并通过其他渠道（私聊、邮件等）发给申请人。

### 6.3 拒绝

```
POST /api/admin/exemption/reject/1
Content-Type: application/json

{"reason": "理由不充分"}
```

---

## API 接口汇总

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| POST | `/api/exemption/request` | 公开 | 提交豁免申请 |
| GET | `/api/exemption/status/<id>` | 公开（只能查自己IP的） | 查询申请状态 |
| GET | `/api/admin/exemption/pending` | 管理员 | 待审核列表 |
| GET | `/api/admin/exemption/all?status=` | 管理员 | 全部申请 |
| POST | `/api/admin/exemption/approve/<id>` | 管理员 | 批准，返回密钥 |
| POST | `/api/admin/exemption/reject/<id>` | 管理员 | 拒绝 |

---

## 状态流转

```
pending（待审核）
  ├── 管理员批准 → approved（已批准，10分钟有效）
  │     ├── 用户使用 → used（已使用，终态）
  │     └── 10分钟未使用 → expired（已过期，终态）
  └── 管理员拒绝 → rejected（已拒绝，终态）
```

---

## 注意事项

1. **密钥只显示一次**：批准时返回的密钥不会再显示，管理员必须立即复制发给用户
2. **IP 绑定**：用户必须在申请时的同一 IP 上使用密钥，否则验证失败
3. **一次性**：密钥使用后立即失效，即使注册失败也不能重复用
4. **申请频率**：每 IP 每分钟只能申请一次，且不能有 pending 状态的申请
5. **管理员审核**：建议在管理后台加一个审核页面，展示 pending 列表和批准/拒绝按钮
6. **通知用户**：批准后密钥需要管理员手动发给用户（如私聊），系统不会自动通知
