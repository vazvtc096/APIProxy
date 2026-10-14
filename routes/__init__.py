"""路由蓝图注册聚合。

所有路由模块在此统一注册到 Quart app 实例上。
"""
def register_blueprints(app):
    """注册所有路由蓝图到 app 实例。"""
    from .auth import auth_bp
    from .user import user_bp
    from .admin import admin_bp
    from .recharge import recharge_bp
    from .chat_proxy import chat_proxy_bp
    from .openai_extra import openai_extra_bp
    from .claude_compat import claude_bp
    from .gemini_compat import gemini_bp
    from .openai_extra import openai_extra_bp
    from .social import social_bp
    from .oauth_routes import oauth_bp
    from .oidc_routes import oidc_bp
    from .rcon_routes import rcon_bp
    from .console_routes import console_bp
    from .audit_routes import audit_bp
    from .auth_routes import auth_bp as secauth_bp
    from .pages import pages_bp
    from .email_captcha import email_captcha_bp
    from .health import health_bp
    from .cluster_routes import cluster_bp
    from ..cache_store import cache_bp
    from .notifications_routes import notif_bp
    from .playground import playground_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(recharge_bp)
    app.register_blueprint(chat_proxy_bp)
    app.register_blueprint(openai_extra_bp)
    app.register_blueprint(claude_bp)
    app.register_blueprint(gemini_bp)
    app.register_blueprint(social_bp)
    app.register_blueprint(oauth_bp)
    app.register_blueprint(oidc_bp)
    app.register_blueprint(rcon_bp)
    app.register_blueprint(console_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(secauth_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(email_captcha_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(cluster_bp)
    app.register_blueprint(cache_bp)
    app.register_blueprint(notif_bp)
    app.register_blueprint(playground_bp)
