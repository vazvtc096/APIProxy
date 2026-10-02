"""文档与使用统计：markdown 文档扫描/渲染、每日用量汇总。

从 core.py 拆分而来（阶段 2：God module 拆分）。
"""
import os

from .core_db import async_db_query


async def _usage_daily(user_name: str = '', days: int = 7) -> dict:
    """返回最近 days 天的日期序列与每日 cost/requests/tokens（可选按用户过滤）"""
    clauses = []
    args: list = []
    if user_name:
        clauses.append('user_name = ?')
        args.append(user_name)
    clauses.append("created_at >= DATE('now', '-' || ? || ' days')")
    args.append(days)
    where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
    sql = f"""
        SELECT DATE(created_at) as date,
               COALESCE(SUM(cost), 0) as cost,
               COUNT(*) as requests,
               COALESCE(SUM(total_tokens), 0) as tokens
        FROM usage_logs
        {where}
        GROUP BY DATE(created_at) ORDER BY date ASC
    """
    rows = await async_db_query(sql, tuple(args)) or []
    data_map = {r['date']: r for r in rows}
    from datetime import datetime, timedelta
    end = datetime.now().date()
    dates, costs, requests, tokens = [], [], [], []
    for i in range(days - 1, -1, -1):
        d = (end - timedelta(days=i)).strftime('%Y-%m-%d')
        rec = data_map.get(d)
        dates.append(d)
        costs.append(round(float(rec['cost'] if rec else 0), 6))
        requests.append(rec['requests'] if rec else 0)
        tokens.append(rec['tokens'] if rec else 0)
    return {'dates': dates, 'costs': costs, 'requests': requests, 'tokens': tokens}


async def _usage_daily_by_model(user_name: str = '', days: int = 7, top_n: int = 6) -> dict:
    """按 天 x 模型 交叉聚合用量（供 DeepSeek 风格堆叠柱状图）。

    返回与 _usage_daily 相同的日期轴，外加每个模型的每日 cost/requests/tokens 序列：
    {'dates': [...], 'models': ['m1', 'm2', '其他'],
     'costs': {'m1': [..], ...}, 'requests': {...}, 'tokens': {...}}
    模型按区间总费用取 top_n，其余（若超出）合并进 '其他'。
    """
    clauses = []
    args: list = []
    if user_name:
        clauses.append('user_name = ?')
        args.append(user_name)
    clauses.append("created_at >= DATE('now', '-' || ? || ' days')")
    args.append(days)
    where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
    sql = f"""
        SELECT DATE(created_at) as date,
               COALESCE(model, '未知模型') as model,
               COALESCE(SUM(cost), 0) as cost,
               COUNT(*) as requests,
               COALESCE(SUM(total_tokens), 0) as tokens
        FROM usage_logs
        {where}
        GROUP BY DATE(created_at), model
    """
    rows = await async_db_query(sql, tuple(args)) or []
    from datetime import datetime, timedelta
    end = datetime.now().date()

    # 模型按区间总费用排序取 top_n；超出部分合并为 '其他'
    totals: dict = {}
    for r in rows:
        t = totals.setdefault(r['model'], [0.0, 0, 0])
        t[0] += float(r['cost'] or 0)
        t[1] += r['requests']
        t[2] += r['tokens']
    ordered = sorted(totals.items(), key=lambda kv: kv[1][0], reverse=True)
    top = [m for m, _ in ordered[:top_n]]
    has_other = len(ordered) > top_n
    if has_other:
        top.append('其他')

    def bucket(model: str):
        if model in top:
            return model
        return '其他' if has_other else None

    date_idx: dict = {}
    dates = []
    for i in range(days - 1, -1, -1):
        d = (end - timedelta(days=i)).strftime('%Y-%m-%d')
        date_idx[d] = days - 1 - i
        dates.append(d)

    costs = {m: [0.0] * days for m in top}
    requests = {m: [0] * days for m in top}
    tokens = {m: [0] * days for m in top}
    for r in rows:
        di = date_idx.get(r['date'])
        if di is None:
            continue
        b = bucket(r['model'])
        if b is None:
            continue  # 模型数量未超 top_n 时理论上不会走到这里
        costs[b][di] += float(r['cost'] or 0)
        requests[b][di] += r['requests']
        tokens[b][di] += r['tokens']
    for m in top:
        costs[m] = [round(v, 6) for v in costs[m]]
    return {'dates': dates, 'models': top, 'costs': costs,
            'requests': requests, 'tokens': tokens}


DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'docs')


def _doc_meta(text):
    """从 markdown 提取首个 # 标题与首个 > 简介。"""
    title = ''
    intro = ''
    for line in text.splitlines():
        if not title and line.startswith('# '):
            title = line[2:].strip()
        elif not intro and line.lstrip().startswith('>'):
            intro = line.lstrip()[1:].strip()
            break
    return title, intro


def _scan_docs():
    """扫描 docs/ 下所有 .md，返回 [{slug, title, intro}]（按文件名排序）。"""
    import glob
    docs = []
    for path in sorted(glob.glob(os.path.join(DOCS_DIR, '*.md'))):
        slug = os.path.splitext(os.path.basename(path))[0].lower()
        try:
            with open(path, 'r', encoding='utf-8') as f:
                text = f.read()
        except Exception:
            continue
        title, intro = _doc_meta(text)
        docs.append({'slug': slug, 'title': title or slug, 'intro': intro})
    return docs


def _load_doc(slug):
    """读取单个 markdown 文档：宏替换 -> 渲染 -> 给 h2 注入锚点 id -> 去除重复简介。"""
    import re
    from quart import request
    # 安全：slug 仅允许小写字母、数字、连字符、下划线，防止路径穿越
    if not re.match(r'^[a-z0-9_-]+$', slug):
        return None
    path = os.path.join(DOCS_DIR, slug + '.md')
    if not os.path.isfile(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    title, intro = _doc_meta(text)
    # 去掉正文开头的 H1 标题行：标题已由模板的 <h1>{{ doc.title }}</h1> 渲染，
    # 否则 markdown 里的 # 标题会再生成一层 <h1>，造成重复。
    text = re.sub(r'^# .*$', '', text, count=1, flags=re.M)
    toc = [ln[3:].strip() for ln in text.splitlines() if ln.startswith('## ')]
    # 宏替换 {{KEY}}（如 {{BASE_URL}}，随部署域名自动变化）
    macros = {
        'BASE_URL': request.host_url.rstrip('/'),
        'SITE_NAME': 'Cloud LLM API 代理',
    }
    def _rep(m):
        return macros.get(m.group(1), m.group(0))
    text = re.sub(r'\{\{([A-Z0-9_]+)\}\}', _rep, text)
    try:
        import markdown
        html = markdown.markdown(text, extensions=['tables', 'fenced_code'])
    except Exception:
        html = '<pre>' + text + '</pre>'
    # 给每个 <h2> 注入 id 供目录锚点跳转
    n = [0]
    def _h2(_):
        n[0] += 1
        return f'<h2 id="h2-{n[0]}">'
    html = re.sub(r'<h2>', _h2, html)
    # 移除首个 blockquote（已作为简介在页头展示，避免正文重复）
    html = re.sub(r'<blockquote>.*?</blockquote>', '', html, count=1, flags=re.S)
    return {'slug': slug, 'title': title or slug, 'intro': intro, 'toc': toc, 'html': html}
