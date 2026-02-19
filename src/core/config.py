import os
import json

class ConfigManager:
    #Управление настройками приложения.
    #Требование: ARC-2, CFG-3
    def __init__(self, profile: str = "default"):
        self.profile = profile
        self.config_dir = os.path.join(os.path.expanduser("~"), ".cryptosafe")
        self.config_file = os.path.join(self.config_dir, f"config_{profile}.json")
        self._ensure_config_dir()
        self.settings = self._load_config()

    def _ensure_config_dir(self):
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

    def _load_config(self) -> dict:
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return self._default_settings()

    def _default_settings(self) -> dict:
        return {
            "db_path": os.path.join(self.config_dir, "vault.db"),
            "clipboard_timeout": 30,
            "auto_lock_timeout": 5,
            "theme": "light"
        }

    def get(self, key: str, default=None):
        return self.settings.get(key, default)

    def set(self, key: str, value):
        self.settings[key] = value
        self._save()

    def _save(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.settings, f, indent=4)