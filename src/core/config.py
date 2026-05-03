import base64
import json
import logging
import os
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.key_manager import KeyManager
    from src.database.db import DatabaseHelper

logger = logging.getLogger("ConfigManager")

CLIPBOARD_PRESETS = {
    "Standard": {
        "clipboard_timeout": 30,
        "clipboard_auto_clear": True,
        "clipboard_monitor_enabled": True,
        "clipboard_block_on_suspicious": False,
        "clipboard_security_level": "basic",
        "clipboard_notify_on_copy": True,
        "clipboard_notify_on_clear": True,
        "clipboard_notify_on_warning": True,
    },
    "Secure": {
        "clipboard_timeout": 15,
        "clipboard_auto_clear": True,
        "clipboard_monitor_enabled": True,
        "clipboard_block_on_suspicious": True,
        "clipboard_security_level": "advanced",
        "clipboard_notify_on_copy": True,
        "clipboard_notify_on_clear": True,
        "clipboard_notify_on_warning": True,
    },
    "Public Computer": {
        "clipboard_timeout": 5,
        "clipboard_auto_clear": True,
        "clipboard_monitor_enabled": True,
        "clipboard_block_on_suspicious": True,
        "clipboard_security_level": "paranoid",
        "clipboard_notify_on_copy": True,
        "clipboard_notify_on_clear": True,
        "clipboard_notify_on_warning": True,
    },
}

ENCRYPTED_SETTING_PREFIXES = ("clipboard_",)


class ConfigManager:
    def __init__(self, profile: str = "default"):
        self.profile = profile
        self.config_dir = os.path.join(os.path.expanduser("~"), ".cryptosafe")
        self.config_file = os.path.join(self.config_dir, f"config_{profile}.json")
        self._db_helper: Optional["DatabaseHelper"] = None
        self._key_manager: Optional["KeyManager"] = None

        self._ensure_config_dir()
        self.settings = self._default_settings()
        self._load_meta_config()

    def _ensure_config_dir(self):
        os.makedirs(self.config_dir, exist_ok=True)

    def _default_settings(self) -> dict:
        return {
            "clipboard_timeout": 30,
            "clipboard_auto_clear": True,
            "clipboard_monitor_enabled": True,
            "clipboard_block_on_suspicious": False,
            "clipboard_security_level": "basic",
            "clipboard_notify_on_copy": True,
            "clipboard_notify_on_clear": True,
            "clipboard_notify_on_warning": True,
            "clipboard_allowed_applications": [],
            "clipboard_profile": "Standard",
            "auto_lock_timeout": 5,
            "theme": "light",
        }

    def _load_meta_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.db_path = data.get("db_path", os.path.join(self.config_dir, "vault.db"))
        else:
            self.db_path = os.path.join(self.config_dir, "vault.db")
            self._save_meta_config()

    def _save_meta_config(self):
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump({"db_path": self.db_path}, f, indent=4)

    def attach_database(self, db_helper: "DatabaseHelper"):
        self._db_helper = db_helper
        self._load_settings_from_db()

    def attach_key_manager(self, key_manager: "KeyManager"):
        self._key_manager = key_manager
        self._load_settings_from_db()

    def _load_settings_from_db(self):
        if not self._db_helper:
            return

        rows = self._db_helper.fetchall("SELECT setting_key, setting_value, encrypted FROM settings")
        for key, value, encrypted in rows:
            try:
                if encrypted:
                    if not self._key_manager:
                        continue
                    value = self._decrypt_setting_value(value)
                self.settings[key] = self._deserialize_value(value)
            except Exception as e:
                logger.warning(f"Failed to load setting {key}: {e}")

    def get(self, key: str, default=None):
        return self.settings.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def get_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, default))
        except (TypeError, ValueError):
            return default

    def set(self, key: str, value: Any):
        self.settings[key] = value
        if key == "db_path":
            self.db_path = value
            self._save_meta_config()

        if not self._db_helper:
            return

        serialized_value = self._serialize_value(value)
        encrypted = 0
        if self._should_encrypt_setting(key) and self._key_manager:
            serialized_value = self._encrypt_setting_value(serialized_value)
            encrypted = 1

        exists = self._db_helper.fetchone("SELECT 1 FROM settings WHERE setting_key = ?", (key,))
        if exists:
            self._db_helper.execute(
                "UPDATE settings SET setting_value = ?, encrypted = ? WHERE setting_key = ?",
                (serialized_value, encrypted, key),
            )
        else:
            self._db_helper.execute(
                "INSERT INTO settings (setting_key, setting_value, encrypted) VALUES (?, ?, ?)",
                (key, serialized_value, encrypted),
            )

    def get_clipboard_settings(self) -> dict:
        return {
            "timeout": self.get_int("clipboard_timeout", 30),
            "auto_clear": self.get_bool("clipboard_auto_clear", True),
            "monitor_enabled": self.get_bool("clipboard_monitor_enabled", True),
            "block_on_suspicious": self.get_bool("clipboard_block_on_suspicious", False),
            "security_level": self.get("clipboard_security_level", "basic"),
            "notify_on_copy": self.get_bool("clipboard_notify_on_copy", True),
            "notify_on_clear": self.get_bool("clipboard_notify_on_clear", True),
            "notify_on_warning": self.get_bool("clipboard_notify_on_warning", True),
            "allowed_applications": self.get("clipboard_allowed_applications", []),
            "profile": self.get("clipboard_profile", "Standard"),
        }

    def set_clipboard_settings(self, values: dict):
        key_map = {
            "timeout": "clipboard_timeout",
            "auto_clear": "clipboard_auto_clear",
            "monitor_enabled": "clipboard_monitor_enabled",
            "block_on_suspicious": "clipboard_block_on_suspicious",
            "security_level": "clipboard_security_level",
            "notify_on_copy": "clipboard_notify_on_copy",
            "notify_on_clear": "clipboard_notify_on_clear",
            "notify_on_warning": "clipboard_notify_on_warning",
            "allowed_applications": "clipboard_allowed_applications",
            "profile": "clipboard_profile",
        }
        for key, value in values.items():
            self.set(key_map.get(key, key), value)

    def apply_clipboard_profile(self, profile_name: str):
        if profile_name not in CLIPBOARD_PRESETS:
            raise ValueError(f"Unknown clipboard profile: {profile_name}")
        for key, value in CLIPBOARD_PRESETS[profile_name].items():
            self.set(key, value)
        self.set("clipboard_profile", profile_name)

    def _should_encrypt_setting(self, key: str) -> bool:
        return key.startswith(ENCRYPTED_SETTING_PREFIXES)

    @staticmethod
    def _serialize_value(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)

    @staticmethod
    def _deserialize_value(value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return value

    def _encrypt_setting_value(self, value: str) -> str:
        if not self._key_manager:
            raise RuntimeError("KeyManager is required to encrypt settings")
        from core.vault.encryption_service import AES256GCMService

        service = AES256GCMService()
        service.set_key_manager(self._key_manager)
        encrypted = service.encrypt(value.encode("utf-8"), associated_data=b"settings")
        return base64.b64encode(encrypted).decode("ascii")

    def _decrypt_setting_value(self, value: str) -> str:
        if not self._key_manager:
            raise RuntimeError("KeyManager is required to decrypt settings")
        from core.vault.encryption_service import AES256GCMService

        service = AES256GCMService()
        service.set_key_manager(self._key_manager)
        encrypted = base64.b64decode(value.encode("ascii"))
        return service.decrypt(encrypted, associated_data=b"settings").decode("utf-8")
