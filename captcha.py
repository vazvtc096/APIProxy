"""
滑块验证码模块（SMTP 未配置时注册流程的兜底验证）

与 email_utils 类似的纯内存实现，不依赖任何外部服务 / 第三方库。
后端保存每次挑战的目标位置与过期时间，前端渲染缺口并拖拽，提交后由后端校验。
"""
import time
import uuid
import secrets
from typing import Tuple

# 滑块参数
CAPTCHA_TRACK_WIDTH = 300    # 轨道宽度（像素）
CAPTCHA_TRACK_HEIGHT = 44    # 轨道高度（像素）
CAPTCHA_GAP_SIZE = 42        # 缺口 / 滑块宽度（像素）
CAPTCHA_TOLERANCE = 6        # 校验容差（像素）
CAPTCHA_EXPIRE_SECONDS = 300  # 单次挑战有效期（5 分钟）
CAPTCHA_SIDE_MARGIN = 10     # 缺口距两端最小边距


# 挑战存储：{token: {'target_x': int, 'expire_at': float, 'used': bool}}
_slider_captchas = {}


def _cleanup_expired() -> None:
    now = time.time()
    expired = [t for t, r in _slider_captchas.items() if now > r['expire_at']]
    for t in expired:
        _slider_captchas.pop(t, None)


def generate_slider_captcha() -> dict:
    """生成滑块验证码，返回前端渲染所需数据

    Returns:
        {
            'token': str,          # 本次挑战的唯一标识（提交时回传）
            'track_width': int,
            'track_height': int,
            'gap_size': int,
            'target_x': int,       # 缺口左边界（用于渲染，也作为校验基准）
        }
    """
    _cleanup_expired()

    token = uuid.uuid4().hex
    min_x = CAPTCHA_SIDE_MARGIN
    max_x = CAPTCHA_TRACK_WIDTH - CAPTCHA_GAP_SIZE - CAPTCHA_SIDE_MARGIN
    target_x = min_x + secrets.randbelow(max_x - min_x + 1)

    _slider_captchas[token] = {
        'target_x': target_x,
        'expire_at': time.time() + CAPTCHA_EXPIRE_SECONDS,
        'used': False,
    }

    return {
        'token': token,
        'track_width': CAPTCHA_TRACK_WIDTH,
        'track_height': CAPTCHA_TRACK_HEIGHT,
        'gap_size': CAPTCHA_GAP_SIZE,
        'target_x': target_x,
    }


def verify_slider_captcha(token: str, x) -> Tuple[bool, str]:
    """校验滑块验证码

    Args:
        token: generate_slider_captcha 返回的 token
        x: 用户拖动后滑块的左边界像素值

    Returns:
        (success: bool, message: str)
    """
    rec = _slider_captchas.get(token)
    if not rec:
        return False, "验证码无效或已过期，请刷新"
    if time.time() > rec['expire_at']:
        _slider_captchas.pop(token, None)
        return False, "验证码已过期，请刷新"
    if rec['used']:
        return False, "验证码已被使用，请刷新"

    try:
        x = int(x)
    except (TypeError, ValueError):
        return False, "验证码格式错误"

    if abs(x - rec['target_x']) > CAPTCHA_TOLERANCE:
        return False, "验证失败，请将滑块拖到缺口位置"

    rec['used'] = True
    return True, "验证成功"


def cleanup_expired_captchas() -> None:
    """清理过期的滑块验证码（可定期调用）"""
    _cleanup_expired()
