"""统一错误处理体系。

所有业务代码应抛出 APIError 子类而非手动 return jsonify(...), status。
全局 errorhandler 会捕获并格式化为统一 JSON 响应。
"""
import logging
import traceback
from quart import jsonify

logger = logging.getLogger(__name__)


class APIError(Exception):
    """API 错误基类。

    Attributes:
        code: 机器可读的错误码（如 "AUTH_FAILED", "RATE_LIMITED"）
        message: 人类可读的错误描述
        http_status: HTTP 状态码
    """

    def __init__(self, code: str = "INTERNAL_ERROR", message: str = "Internal server error",
                 http_status: int = 500, details: dict | None = None):
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict:
        d = {"error": self.code, "message": self.message}
        if self.details:
            d["details"] = self.details
        return d


class AuthError(APIError):
    def __init__(self, message: str = "Authentication required", details: dict | None = None):
        super().__init__("AUTH_FAILED", message, 401, details)


class ForbiddenError(APIError):
    def __init__(self, message: str = "Forbidden", details: dict | None = None):
        super().__init__("FORBIDDEN", message, 403, details)


class NotFoundError(APIError):
    def __init__(self, message: str = "Resource not found", details: dict | None = None):
        super().__init__("NOT_FOUND", message, 404, details)


class ValidationError(APIError):
    def __init__(self, message: str = "Validation failed", details: dict | None = None):
        super().__init__("VALIDATION_ERROR", message, 400, details)


class ConflictError(APIError):
    def __init__(self, message: str = "Conflict", details: dict | None = None):
        super().__init__("CONFLICT", message, 409, details)


class RateLimitError(APIError):
    def __init__(self, message: str = "Rate limit exceeded", details: dict | None = None):
        super().__init__("RATE_LIMITED", message, 429, details)


class PaymentRequiredError(APIError):
    def __init__(self, message: str = "Insufficient balance", details: dict | None = None):
        super().__init__("PAYMENT_REQUIRED", message, 402, details)


def register_error_handlers(app):
    """在 Quart 应用上注册全局错误处理器。"""

    @app.errorhandler(APIError)
    async def handle_api_error(e: APIError):
        if e.http_status >= 500:
            logger.error(f"APIError [{e.code}]: {e.message}", exc_info=True)
        else:
            logger.warning(f"APIError [{e.code}]: {e.message}")
        return jsonify(e.to_dict()), e.http_status

    @app.errorhandler(404)
    async def handle_404(e):
        return jsonify({"error": "NOT_FOUND", "message": "The requested resource was not found"}), 404

    @app.errorhandler(405)
    async def handle_405(e):
        return jsonify({"error": "METHOD_NOT_ALLOWED", "message": "The requested method is not allowed"}), 405

    @app.errorhandler(500)
    async def handle_500(e):
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        return jsonify({"error": "INTERNAL_ERROR", "message": "An internal server error occurred"}), 500

    @app.errorhandler(Exception)
    async def handle_unexpected(e: Exception):
        if isinstance(e, APIError):
            return jsonify(e.to_dict()), e.http_status
        logger.error(f"Unexpected exception: {e}", exc_info=True)
        return jsonify({"error": "INTERNAL_ERROR", "message": "An internal server error occurred"}), 500
