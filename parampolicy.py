"""请求参数治理：max_tokens 上限 + temperature/top_p 范围白名单。

目的：防止单请求用超大 max_tokens 刷爆计费/上游配额。校验在请求入口
（chat/responses/claude/raw 端点）执行，超限直接 400，不进任务队列。

config.yaml:
    param_limits:
      enabled: true
      max_tokens_cap: 16384      # 0 = 不限制；校验 max_tokens/max_output_tokens
      temperature_range: [0, 2]
      top_p_range: [0, 1]
"""
from . import configs


def validate(payload: dict) -> tuple:
    """校验请求参数，返回 (ok, reason)。异常时 fail-open（不阻断主链路）。"""
    try:
        cfg = getattr(configs, 'PARAM_LIMITS', None) or {}
        if not cfg.get('enabled', True) or not isinstance(payload, dict):
            return True, ''

        cap = int(cfg.get('max_tokens_cap') or 0)
        if cap > 0:
            mt = payload.get('max_tokens')
            if mt is None:
                mt = payload.get('max_output_tokens')      # OpenAI Responses API
            if mt is None:
                mt = payload.get('max_completion_tokens')  # 新版 Chat API 别名
            if mt is not None:
                try:
                    mt = int(mt)
                except (TypeError, ValueError):
                    return False, 'max_tokens must be an integer'
                if mt < 1:
                    return False, 'max_tokens must be >= 1'
                if mt > cap:
                    return False, f'max_tokens {mt} exceeds limit {cap}'

        for field in ('temperature', 'top_p'):
            v = payload.get(field)
            rng = cfg.get(f'{field}_range')
            if v is not None and rng and len(rng) == 2:
                try:
                    v = float(v)
                except (TypeError, ValueError):
                    return False, f'{field} must be a number'
                lo, hi = float(rng[0]), float(rng[1])
                if not (lo <= v <= hi):
                    return False, f'{field} {v} out of range [{lo}, {hi}]'
        return True, ''
    except Exception:
        return True, ''  # 治理层自身故障不阻断请求
