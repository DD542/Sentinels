"""
Logs structures JSON — une ligne JSON par evenement sur stdout
(12-factor : Docker, Loki, ELK, CloudWatch les ingerent tels quels).

- logs.configure() : installe le format (appele au demarrage, idempotent).
  LOG_FORMAT=text bascule en format lisible pour le dev local.
- logs.get_logger("audit") : logger nomme "sentinel.audit".
- Les champs passes via extra={...} deviennent des cles JSON de premier
  niveau : log.info("decision", extra={"event": "decision", ...}).
"""
from __future__ import annotations
import json
import logging
import sys
from datetime import datetime, timezone

from .config import get_settings

settings = get_settings()

# Attributs standard de LogRecord : tout le reste (extra) part dans le JSON.
_STD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc)
                          .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STD_ATTRS and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure() -> None:
    """Installe le handler sur le logger racine 'sentinel' (idempotent).
    En mode JSON, aligne aussi les loggers uvicorn deja configures pour
    que TOUTE la sortie du process soit du JSON homogene."""
    if settings.log_format == "text":
        formatter: logging.Formatter = logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s — %(message)s")
    else:
        formatter = JsonFormatter()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger("sentinel")
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    root.propagate = False

    if settings.log_format != "text":
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            for h in logging.getLogger(name).handlers:
                h.setFormatter(formatter)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"sentinel.{name}")
