"""前端页面路由"""
from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for, send_file
from ..app import app
from ..core import *
from .. import social, oauth, upstreams, pricing
from .. import hooks as _hooks
from .. import announcements as _ann
from ..apikey import APIKey, hash_password, verify_password, generate_uid, _get_user_by_name, _verify_user_password
from ..configs import BASEURL, APIKEY, RCON_ENABLED, RCON_SECRET, SSL_ENABLED, SESSION_SECRET, OAUTH_JWT_SECRET, SMTP_CONFIGURED
from .. import configs
from ..constants import CHAR_PRICE_LOOKUP, UNEXCEPT_CHAR, MONEY_PER_MILLION_TOKENS, UNEXCEPT_MODEL, MAX_OVERDRAFT
from ..cloudflare import get_client_ip as _cf_get_client_ip
from .. import waf as _waf

pages_bp = Blueprint('pages', __name__)


# ---------- 站点图标 ----------
import os as _os
# pages.py 位于 APIProxy/routes/ 下：上溯两级即 APIProxy 包根，static 在其下
_STATIC_DIR = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "static")


@pages_bp.route('/favicon.ico', methods=['GET'])
async def favicon_ico():
    """站点图标（浏览器默认请求路径），无会话要求，长缓存。"""
    return await send_file(_os.path.join(_STATIC_DIR, "favicon.ico"),
                           mimetype="image/x-icon",
                           cache_timeout=86400)


@pages_bp.route('/favicon.svg', methods=['GET'])
async def favicon_svg():
    """站点图标矢量版（现代浏览器优先使用）。"""
    return await send_file(_os.path.join(_STATIC_DIR, "favicon.svg"),
                           mimetype="image/svg+xml",
                           cache_timeout=86400)


@pages_bp.route('/api/rcon', methods=['POST'])
async def rcon_execute():
    """RCON 远程命令执行"""
    # 兼容反向代理 / Cloudflare：取真实客户端 IP
    # 注意：必须在两条认证分支之外取值——下方日志无条件引用它，
    # 若只在密钥分支里赋值，管理员会话路径会在命令执行后抛 NameError（历史 Bug）。
    client_ip = _get_client_ip()

    # 方式一：Session 管理员认证（网页终端使用）
    is_admin_session = await _is_admin()
    
    # 方式二：RCON 密钥认证（API 调用使用）
    rcon_key = request.headers.get('X-RCON-Key', '')
    if not rcon_key:
        data = await request.get_json(silent=True)
        if data:
            rcon_key = data.get('key', '')
    
    # 验证认证方式
    # 管理员会话（网页终端）直接放行；其余必须凭有效的 RCON 密钥。
    # 注意：密钥校验绝不能写在上面的 `if` 分支里（会被 return 短路成死代码）。
    if not is_admin_session:
        if not rcon_key:
            return jsonify({'error': 'Authentication required'}), 401
        # 验证密钥（恒定时间比较，防时序攻击）
        valid = await _validate_rcon_key(rcon_key, client_ip)
        if not valid:
            return jsonify({'error': 'Invalid RCON key'}), 401
    
    # 获取命令
    data = await request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Command required'}), 400
    
    command = data.get('command', '').strip()
    args = data.get('args', [])
    
    if not command:
        return jsonify({'error': 'Command required'}), 400
    
    # 执行命令
    result = await _execute_rcon_command(command, args)
    
    # 记录日志
    logging.info(f"RCON command executed: {command} {args}, from {client_ip}")
    
    return jsonify(result), 200 if result['success'] else 400



@pages_bp.route('/')
async def index():
    """根路径：已登录跳转到仪表板，未登录跳转到登录页"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))



@pages_bp.route('/dashboard')
@pages_bp.route('/dashboard/<section>')
async def dashboard(section='overview'):
    """主仪表板页面（按 section 渲染对应页签，每个页签独立地址）"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    if section not in _ALLOWED_SECTIONS:
        return redirect(url_for('dashboard'))
    active = 'dashboard' if section == 'overview' else section
    return await render_template('dashboard.html', section=section, active_page=active)




@pages_bp.route('/friends')
async def friends():
    """好友页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('friends.html')



@pages_bp.route('/chat')
async def chat():
    """聊天页面"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('chat.html')



@pages_bp.route('/social')
async def social_home():
    """社交首页 - 帖子广场"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_posts.html')


@pages_bp.route('/social/posts')
async def social_posts_plaza():
    """帖子广场（与 /social 等价，供帖子详情页「返回帖子广场」回退）"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('social_posts.html')


@pages_bp.route('/notifications')
async def notifications_page():
    """通知中心（铃铛的完整视图）。"""
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return await render_template('notifications.html')


@pages_bp.route('/docs')
async def docs_page():
    """文档中心：动态列出 docs/ 下所有 markdown 指南。"""
    return await render_template('docs_hub.html', docs=_scan_docs())



@pages_bp.route('/docs/<slug>')
async def docs_doc_page(slug):
    """单个 markdown 文档页（动态加载，含本页目录）。"""
    doc = _load_doc(slug)
    if not doc:
        return '<h1>文档未找到</h1><p>请求的文档不存在。</p>', 404
    return await render_template('doc_page.html', doc=doc, docs=_scan_docs(), active=slug)


# 文档页改由 templates/doc_page.html 动态渲染（见 _load_doc / docs_doc_page）。


# ========== RCON Web 控制台（独立认证体系） ==========


@pages_bp.route('/rcon')
async def rcon_index():
    """RCON 首页 - 未登录跳转到登录页"""
    if _is_rcon_authenticated():
        return redirect(url_for('rcon_terminal_page'))
    return redirect(url_for('rcon_login_page'))



