"""邮箱验证码与滑块验证码路由"""
from quart import Blueprint, request, session, jsonify, Response, render_template, redirect, url_for
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

email_captcha_bp = Blueprint('email_captcha', __name__)

@email_captcha_bp.route('/api/email/send-code', methods=['POST'])
async def send_email_code():
    """发送邮箱验证码"""
    # 限流检查
    allowed, remaining = _check_rate_limit('register')
    if not allowed:
        return jsonify({'error': 'Too many requests, please try again later'}), 429, {'Retry-After': str(_get_rate_limit_retry_after('register'))}
    
    data = await request.get_json() or {}
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    # 简单的邮箱格式验证
    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Invalid email format'}), 400
    
    try:
        from ..email_utils import send_verification_email
        success, msg = send_verification_email(email)
        if success:
            return jsonify({'message': 'Verification code sent'}), 200
        else:
            return jsonify({'error': msg}), 400
    except Exception as e:
        logging.error(f"Send email code error: {e}")
        return jsonify({'error': 'Failed to send verification code'}), 500


# ---------- 滑块验证码相关路由（SMTP 未配置时替代邮箱验证） ----------

@email_captcha_bp.route('/api/captcha/mode', methods=['GET'])
async def captcha_mode():
    """返回当前验证模式，前端据此决定显示邮箱验证还是滑块验证码"""
    return jsonify({'smtp_configured': SMTP_CONFIGURED}), 200



@email_captcha_bp.route('/api/captcha/slider', methods=['GET'])
async def captcha_slider():
    """获取滑块验证码数据（缺口位置 / 尺寸 / token）"""
    from ..captcha import generate_slider_captcha
    return jsonify(generate_slider_captcha()), 200


# ---------- 删除 API Key 路由 ----------

