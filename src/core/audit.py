import json
import logging
from typing import TYPE_CHECKING

from .events import Event, event_bus

if TYPE_CHECKING:
    from src.database.db import DatabaseHelper

logger = logging.getLogger("AuditSystem")


class AuditManager:
    def __init__(self, db_helper: "DatabaseHelper"):
        self.db = db_helper
        self._subscribe()

    def _subscribe(self):
        event_bus.subscribe("EntryAdded", self._log_action)
        event_bus.subscribe("EntryCreated", self._log_action)
        event_bus.subscribe("EntryUpdated", self._log_action)
        event_bus.subscribe("EntryDeleted", self._log_action)
        event_bus.subscribe("EntryRestored", self._log_action)
        event_bus.subscribe("UserLoggedIn", self._log_action)
        event_bus.subscribe("ClipboardCopied", self._log_clipboard_event)
        event_bus.subscribe("ClipboardCleared", self._log_clipboard_event)
        event_bus.subscribe("ClipboardSuspiciousActivity", self._log_clipboard_event)
        event_bus.subscribe("ClipboardClearAccelerated", self._log_clipboard_event)
        event_bus.subscribe("ClipboardWarning", self._log_clipboard_event)
        event_bus.subscribe("ClipboardCopyBlockChanged", self._log_clipboard_event)
        event_bus.subscribe("ClipboardError", self._log_clipboard_event)
        event_bus.subscribe("ClipboardMonitorError", self._log_clipboard_event)
        logger.info("AuditManager subscribed to events")

    def _log_action(self, event: Event):
        try:
            details = json.dumps(self._sanitize_general_payload(event.data), ensure_ascii=False, sort_keys=True)
            self.db.execute(
                "INSERT INTO audit_log (action, details) VALUES (?, ?)",
                (event.name, details),
            )
            logger.debug("Audit event written: %s", event.name)
        except Exception as exc:
            logger.error("Audit write error: %s", exc)

    def _log_clipboard_event(self, event: Event):
        try:
            payload = self._sanitize_clipboard_payload(event.data)
            self.db.execute(
                "INSERT INTO audit_log (action, entry_id, details) VALUES (?, ?, ?)",
                (event.name, payload.get("entry_id"), json.dumps(payload, ensure_ascii=False, sort_keys=True)),
            )
            logger.debug("Clipboard audit written: %s", event.name)
        except Exception as exc:
            logger.error("Clipboard audit write error: %s", exc)

    @staticmethod
    def _sanitize_clipboard_payload(data) -> dict:
        if not isinstance(data, dict):
            return {}

        allowed_keys = {
            "action",
            "backend_name",
            "blocked",
            "cleared",
            "count",
            "data_type",
            "message",
            "manual_clear_required",
            "reason",
            "remaining_seconds",
            "source_entry_id",
            "timeout",
        }
        payload = {key: value for key, value in data.items() if key in allowed_keys}
        if "source_entry_id" in payload:
            payload["entry_id"] = payload.pop("source_entry_id")
        return payload

    @classmethod
    def _sanitize_general_payload(cls, data):
        if not isinstance(data, dict):
            return data or {}

        blocked_keys = {"password", "totp_secret", "secret", "key", "encrypted_data"}
        sanitized = {}
        for key, value in data.items():
            if key in blocked_keys:
                sanitized[key] = "[redacted]"
            elif isinstance(value, dict):
                sanitized[key] = cls._sanitize_general_payload(value)
            else:
                sanitized[key] = value
        return sanitized
