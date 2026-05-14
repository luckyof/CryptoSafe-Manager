import hashlib
import json
import logging
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.events import Event, event_bus

from .log_signer import AuditLogSigner
from .log_verifier import AuditLogVerifier

logger = logging.getLogger("AuditLogger")

ZERO_HASH = "0" * 64
REDACTED = "[REDACTED]"
VALID_SEVERITIES = {"INFO", "WARN", "ERROR", "CRITICAL"}
CRITICAL_SEVERITIES = {"ERROR", "CRITICAL"}
ASYNC_QUEUE_SIZE = 1000


class AuditLogger:
    """Журнал аудита на базе событий с полями целостности Sprint 5."""

    EVENT_CATALOG = {
        "LoginSucceeded": ("INFO", "auth"),
        "LoginFailed": ("WARN", "auth"),
        "UserLoggedIn": ("INFO", "auth"),
        "UserLoggedOut": ("INFO", "auth"),
        "PasswordChanged": ("WARN", "auth"),
        "PasswordChangeFailed": ("ERROR", "auth"),
        "FailedAuthAttempt": ("WARN", "auth"),
        "EntryCreated": ("INFO", "vault"),
        "EntryRead": ("INFO", "vault"),
        "EntryViewed": ("INFO", "vault"),
        "EntryUpdated": ("INFO", "vault"),
        "EntryDeleted": ("WARN", "vault"),
        "EntryRestored": ("INFO", "vault"),
        "EntrySearch": ("INFO", "vault"),
        "VaultSearch": ("INFO", "vault"),
        "ClipboardCopied": ("INFO", "clipboard"),
        "ClipboardCleared": ("INFO", "clipboard"),
        "ClipboardAutoCleared": ("INFO", "clipboard"),
        "ClipboardSuspiciousActivity": ("WARN", "clipboard"),
        "ClipboardClearAccelerated": ("WARN", "clipboard"),
        "ClipboardWarning": ("WARN", "clipboard"),
        "ClipboardCopyBlockChanged": ("WARN", "clipboard"),
        "ClipboardError": ("ERROR", "clipboard"),
        "ClipboardMonitorError": ("ERROR", "clipboard"),
        "ConfigChanged": ("INFO", "config"),
        "SettingChanged": ("INFO", "config"),
        "SettingsSaved": ("INFO", "config"),
        "ApplicationStarted": ("INFO", "system"),
        "ApplicationShutdown": ("INFO", "system"),
        "ApplicationClosed": ("INFO", "system"),
        "VaultLocked": ("INFO", "system"),
        "VaultUnlocked": ("INFO", "system"),
        "SessionLocked": ("INFO", "system"),
        "SessionUnlocked": ("INFO", "system"),
        "SuspiciousActivity": ("WARN", "security"),
        "TamperDetected": ("CRITICAL", "security"),
        "SecurityPolicyViolation": ("WARN", "security"),
        "AuditExportCreated": ("WARN", "audit"),
        "AuditExportFailed": ("ERROR", "audit"),
        "SQLInjectionAttempt": ("CRITICAL", "security"),
        "PrivilegeEscalationAttempt": ("CRITICAL", "security"),
        "AuditTamperAttempt": ("CRITICAL", "security"),
        "AuditDisableAttempt": ("CRITICAL", "security"),
    }
    EVENT_DEFAULTS = EVENT_CATALOG

    def __init__(self, db_helper, key_manager=None, signer: Optional[AuditLogSigner] = None, bus=event_bus):
        self.db = db_helper
        self.bus = bus
        self.signer = signer or AuditLogSigner(key_manager=key_manager)
        self.verifier = AuditLogVerifier(db_helper, self.signer, bus=bus)
        self._sequence_lock = threading.Lock()
        self._async_queue = queue.Queue(maxsize=ASYNC_QUEUE_SIZE)
        self._async_stop = threading.Event()
        self._async_worker = None
        self._fallback_sequence = -1
        self._fallback_last_hash = ZERO_HASH
        self._ensure_audit_schema()
        self._store_public_key()
        if hasattr(self.db, "enable_audit_read"):
            self.db.enable_audit_read()
        self._initialize_chain_state()
        self._start_async_worker()
        self._subscribe()
        if hasattr(self.db, "fetchall"):
            self.verify_periodic()

    def _ensure_audit_schema(self):
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

    def _store_public_key(self):
        public_key = self.signer.get_public_key_hex()
        if not public_key or not hasattr(self.db, "fetchone"):
            return

        exists = self.db.fetchone("SELECT 1 FROM audit_keys WHERE key_type = ?", ("audit-signing",))
        if exists:
            self.db.execute(
                "UPDATE audit_keys SET public_key = ?, algorithm = ? WHERE key_type = ?",
                (public_key, self.signer.algorithm, "audit-signing"),
            )
        else:
            self.db.execute(
                "INSERT INTO audit_keys (key_type, public_key, algorithm) VALUES (?, ?, ?)",
                ("audit-signing", public_key, self.signer.algorithm),
            )

    def verify_on_startup(self):
        """Проверить целостность аудита при запуске."""
        return self.verifier.verify_on_startup()

    def verify_periodic(self, sample_size: int = 1000):
        """Проверить свежие записи для фонового контроля."""
        return self.verifier.verify_periodic(sample_size=sample_size)

    def verify_manual(self, export_path: Optional[str] = None):
        """Запустить ручную полную проверку и вернуть отчёт."""
        return self.verifier.verify_manual(export_path=export_path)

    def flush_async(self, timeout: float = 5.0) -> bool:
        """Дождаться записи фоновых событий аудита."""
        if not self._async_worker:
            return True
        self._async_queue.join()
        return True

    def shutdown(self):
        """Остановить фоновую запись аудита."""
        self.flush_async()
        self._async_stop.set()
        if self._async_worker:
            self._async_worker.join(timeout=1.0)

    def log_security_attempt(self, attempt_type: str, details: Optional[Dict[str, Any]] = None) -> int:
        """Записать подозрительную попытку воздействия на аудит или права."""
        event_map = {
            "sql_injection": "SQLInjectionAttempt",
            "privilege_escalation": "PrivilegeEscalationAttempt",
            "tampering": "AuditTamperAttempt",
            "disable_logging": "AuditDisableAttempt",
        }
        event_type = event_map.get(attempt_type, "SecurityPolicyViolation")
        return self.log_event(event_type, severity="CRITICAL", source="security", details=details or {})

    def _subscribe(self):
        for event_name in self.EVENT_CATALOG:
            self.bus.subscribe(event_name, self._log_event_from_bus)
        self.bus.subscribe("EntryAdded", self._log_event_from_bus)
        logger.info("AuditLogger subscribed to security-relevant events")

    def _log_event_from_bus(self, event: Event):
        if isinstance(event.data, dict) and event.data.get("audit_verification_event"):
            return

        severity, source = self._event_defaults(event.name)
        if event.name.startswith("Clipboard"):
            payload = self._sanitize_clipboard_payload(event.data)
        else:
            payload = self._sanitize_payload(event.data)
        entry_id = payload.get("entry_id") or payload.get("source_entry_id")
        if severity in CRITICAL_SEVERITIES:
            self.log_event(
                event_type=event.name,
                severity=severity,
                source=source,
                details=payload,
                entry_id=entry_id,
            )
        else:
            self.log_event_async(
                event_type=event.name,
                severity=severity,
                source=source,
                details=payload,
                entry_id=entry_id,
            )

    def log_event(
        self,
        event_type: str,
        severity: str = "INFO",
        source: str = "application",
        details: Optional[Dict[str, Any]] = None,
        user_id: str = "default_user",
        entry_id: Optional[str] = None,
    ) -> int:
        return self._write_event(event_type, severity, source, details, user_id, entry_id)

    def log_event_async(
        self,
        event_type: str,
        severity: str = "INFO",
        source: str = "application",
        details: Optional[Dict[str, Any]] = None,
        user_id: str = "default_user",
        entry_id: Optional[str] = None,
    ) -> bool:
        if not self._async_worker:
            self.log_event(event_type, severity, source, details, user_id, entry_id)
            return True
        try:
            self._async_queue.put_nowait((event_type, severity, source, details, user_id, entry_id))
            return True
        except queue.Full:
            logger.warning("Audit async queue is full; writing event synchronously")
            self.log_event(event_type, severity, source, details, user_id, entry_id)
            return False

    def _write_event(
        self,
        event_type: str,
        severity: str = "INFO",
        source: str = "application",
        details: Optional[Dict[str, Any]] = None,
        user_id: str = "default_user",
        entry_id: Optional[str] = None,
    ) -> int:
        severity = self._normalize_severity(severity)
        source = source or self._event_defaults(event_type)[1]
        user_id = user_id or "default_user"
        details = self._sanitize_payload(details or {})
        if entry_id is None:
            entry_id = details.get("entry_id") if isinstance(details, dict) else None
        if not hasattr(self.db, "fetchone"):
            return self._log_legacy_event(event_type, details, entry_id)

        with self._sequence_lock:
            sequence_number = self._next_sequence_number()
            previous_hash = self._last_entry_hash()
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "severity": severity,
                "user_id": user_id,
                "source": source,
                "details": details,
                "entry_id": entry_id,
                "sequence_number": sequence_number,
                "previous_hash": previous_hash,
                "signature_algorithm": self.signer.algorithm,
            }

            entry_json = self._canonical_json(entry)
            entry_data = entry_json.encode("utf-8")
            entry_hash = hashlib.sha256(entry_data).hexdigest()
            public_key = self.signer.get_public_key_hex()
            signature = self.signer.sign(entry_data).hex()

            self.db.execute(
                """
                INSERT INTO audit_log
                (sequence_number, previous_hash, entry_data, entry_hash, event_type, action, timestamp, entry_id, details, signature, public_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence_number,
                    previous_hash,
                    entry_data,
                    entry_hash,
                    event_type,
                    event_type,
                    entry["timestamp"],
                    entry_id,
                    json.dumps(entry["details"], ensure_ascii=False, sort_keys=True),
                    signature,
                    public_key,
                ),
            )
            self._fallback_last_hash = entry_hash
        return sequence_number

    def _log_legacy_event(self, event_type: str, details: Dict[str, Any], entry_id: Optional[str]) -> int:
        details = self._legacy_redaction(details)
        details_json = json.dumps(details, ensure_ascii=False, sort_keys=True)
        if event_type.startswith("Clipboard"):
            self.db.execute(
                "INSERT INTO audit_log (action, entry_id, details) VALUES (?, ?, ?)",
                (event_type, entry_id, details_json),
            )
        else:
            self.db.execute(
                "INSERT INTO audit_log (action, details) VALUES (?, ?)",
                (event_type, details_json),
            )
        self._fallback_sequence += 1
        return self._fallback_sequence

    @classmethod
    def _legacy_redaction(cls, value):
        if isinstance(value, dict):
            return {key: cls._legacy_redaction(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._legacy_redaction(item) for item in value]
        if value == REDACTED:
            return "[redacted]"
        return value

    def _next_sequence_number(self) -> int:
        self._fallback_sequence += 1
        return self._fallback_sequence

    def _last_entry_hash(self) -> str:
        return self._fallback_last_hash

    def _initialize_chain_state(self):
        if not hasattr(self.db, "fetchone"):
            return
        row = self.db.fetchone(
            """
            SELECT sequence_number, entry_hash
            FROM audit_log
            WHERE sequence_number IS NOT NULL
            ORDER BY sequence_number DESC
            LIMIT 1
            """
        )
        if row:
            self._fallback_sequence = int(row[0])
            self._fallback_last_hash = row[1] or ZERO_HASH

    def _start_async_worker(self):
        if not hasattr(self.db, "fetchone"):
            return
        self._async_worker = threading.Thread(target=self._async_loop, name="AuditLogWorker", daemon=True)
        self._async_worker.start()

    def _async_loop(self):
        while not self._async_stop.is_set() or not self._async_queue.empty():
            try:
                args = self._async_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._write_event(*args)
            except Exception as error:
                logger.error(f"Async audit write failed: {error}")
            finally:
                self._async_queue.task_done()

    @staticmethod
    def _canonical_json(data: Dict[str, Any]) -> str:
        return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _event_defaults(cls, event_type: str) -> tuple:
        if event_type in cls.EVENT_CATALOG:
            return cls.EVENT_CATALOG[event_type]
        if event_type.startswith("Clipboard"):
            return "INFO", "clipboard"
        if event_type.startswith("Entry") or event_type.startswith("Vault"):
            return "INFO", "vault"
        if "Login" in event_type or "Auth" in event_type or "Password" in event_type:
            return "INFO", "auth"
        if "Config" in event_type or "Setting" in event_type:
            return "INFO", "config"
        if "Suspicious" in event_type or "Tamper" in event_type or "Security" in event_type:
            return "WARN", "security"
        return "INFO", "system"

    @staticmethod
    def _normalize_severity(severity: str) -> str:
        normalized = str(severity or "INFO").upper()
        return normalized if normalized in VALID_SEVERITIES else "INFO"

    @classmethod
    def _sanitize_payload(cls, data):
        if not isinstance(data, dict):
            return data or {}

        blocked_keys = {
            "password",
            "totp_secret",
            "secret",
            "key",
            "encrypted_data",
            "clipboard_content",
        }
        sanitized = {}
        for key, value in data.items():
            lowered_key = str(key).lower()
            if (
                key in blocked_keys
                or "password" in lowered_key
                or "secret" in lowered_key
                or lowered_key in {"key", "encryption_key", "encrypted_data", "clipboard_content"}
            ):
                sanitized[key] = REDACTED
            elif isinstance(value, dict):
                sanitized[key] = cls._sanitize_payload(value)
            elif isinstance(value, list):
                sanitized[key] = [cls._sanitize_payload(item) if isinstance(item, dict) else item for item in value]
            else:
                sanitized[key] = value
        if "source_entry_id" in sanitized and "entry_id" not in sanitized:
            sanitized["entry_id"] = sanitized["source_entry_id"]
        return sanitized

    _sanitize_general_payload = _sanitize_payload

    @classmethod
    def _sanitize_clipboard_payload(cls, data) -> dict:
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

    def _log_action(self, event: Event):
        self._log_event_from_bus(event)

    def _log_clipboard_event(self, event: Event):
        self._log_event_from_bus(event)


AuditManager = AuditLogger
