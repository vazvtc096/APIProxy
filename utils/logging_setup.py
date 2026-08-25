"""统一日志配置：支持文本 / JSON 结构化两种输出格式。

环境变量：
    LOG_FORMAT  = text | json   （默认 text，向后兼容）
    LOG_LEVEL   = DEBUG|INFO|WARNING|ERROR|CRITICAL （默认 INFO）

JSON 格式便于容器环境（docker/kubernetes）由日志采集系统解析聚合，
每条日志一行一个 JSON 对象，字段包含 timestamp / level / logger / message。
"""

import json
import logging
import os
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """输出单行 JSON 的日志格式化器。"""

    # 这些是 logging.LogRecord 的固有字段，无需重复塞进 payload
    _SKIP_ATTRS = frozenset({
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message", "asctime", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .astimezone()
            .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        # 透传调用方通过 extra= 附加的自定义字段
        for key, value in record.__dict__.items():
            if key not in self._SKIP_ATTRS and not key.startswith("_"):
                payload[key] = value

        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging() -> None:
    """按环境变量配置根 logger。幂等：重复调用会重置 handler，避免叠加。"""
    fmt = os.getenv("LOG_FORMAT", "text").strip().lower()
    level_name = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
    root.addHandler(handler)

    # 抑制过于啰嗦的三方库日志，避免淹没业务日志
    for noisy in ("hypercorn.error", "hypercorn.access", "quart.app"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


if __name__ == "__main__":
    setup_logging()
    logging.getLogger("demo").info("结构化日志就绪", extra={"request_id": "abc123"})
    logging.getLogger("demo").warning("这是一条警告")
