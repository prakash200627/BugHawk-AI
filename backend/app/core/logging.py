"""
BugHawk AI 2.0 — Structured Logging
Uses structlog for JSON-formatted, context-aware log output.
"""
import logging
import re
import structlog
from app.config import settings

_CONNECTION_URL = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|amqp|rediss)(?:\+[a-z0-9]+)?://\S+"
)


def redact_connection_urls(value: str) -> str:
    """Remove database and broker URLs, including any userinfo, from a log string."""
    return _CONNECTION_URL.sub(lambda match: match.group(0).split("://", 1)[0] + "://redacted", value)


def configure_logging() -> None:
    """Configure structlog with appropriate processors for the environment."""

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.app_env == "production":
        # JSON output for production log aggregation
        processors = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Pretty console output for development
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.DEBUG if settings.app_debug else logging.INFO
        ),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging
    logging.basicConfig(
        format="%(message)s",
        level=logging.DEBUG if settings.app_debug else logging.INFO,
    )


def get_logger(name: str = "bughawk"):
    return structlog.get_logger(name)
