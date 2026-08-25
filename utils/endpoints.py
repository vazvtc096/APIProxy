"""Endpoint 名兼容层。

蓝图化后 Quart 的 endpoint 会带上蓝图前缀（`login_page` -> `auth.login_page`），
而历史代码与模板中存在大量裸名 `url_for('login_page')` 调用。

逐处改写风险高、易漏。这里改用 Quart/Flask 官方的 `url_build_error_handlers`
钩子：仅在按裸名构建 URL 失败时，回退到「裸名 -> 限定名」的映射重试。
正常的限定名调用完全不受影响，零性能开销。
"""
import logging

from quart import url_for

logger = logging.getLogger(__name__)


def build_alias_map(app):
    """构建 裸 endpoint 名 -> 限定 endpoint 名 的映射。

    若多个蓝图存在同名视图函数，记录告警并保留首个（按 endpoint 字典序稳定）。
    """
    alias = {}
    collisions = {}

    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.endpoint):
        endpoint = rule.endpoint
        if '.' not in endpoint:
            continue
        bare = endpoint.rsplit('.', 1)[1]
        if bare in alias:
            if alias[bare] != endpoint:
                collisions.setdefault(bare, [alias[bare]]).append(endpoint)
            continue
        alias[bare] = endpoint

    for bare, targets in collisions.items():
        logger.warning(
            f"Endpoint 裸名冲突: '{bare}' 对应 {targets}，"
            f"url_for('{bare}') 将解析为 '{alias[bare]}'。建议改用限定名。"
        )

    return alias


def register_endpoint_aliases(app):
    """注册裸 endpoint 名的回退解析。"""
    alias = build_alias_map(app)

    def _resolve_bare_endpoint(error, endpoint, values):
        target = alias.get(endpoint)
        if target and target != endpoint:
            return url_for(target, **values)
        raise error

    app.url_build_error_handlers.append(_resolve_bare_endpoint)
    logger.info(f"Endpoint 兼容层已注册（{len(alias)} 个裸名映射）")
    return alias
