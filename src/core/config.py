import os
import json
from typing import Optional, Any
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from src.database.db import DatabaseHelper

class ConfigManager:
    # Управление настройками приложения.
    # Требование: ARC-2, CFG-2, CFG-3
    
    def __init__(self, profile: str = "default"):
        self.profile = profile
        self.config_dir = os.path.join(os.path.expanduser("~"), ".cryptosafe")
        self.config_file = os.path.join(self.config_dir, f"config_{profile}.json")
        self._ensure_config_dir()
        
        # Инициализируем настройки значениями по умолчанию
        self.settings = self._default_settings()
        # Загружаем метаданные (путь к БД) из файла
        self._load_meta_config()
        
        self._db_helper: Optional['DatabaseHelper'] = None

    def _ensure_config_dir(self):
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

    def _default_settings(self) -> dict:
        return {
            "clipboard_timeout": 30,
            "auto_lock_timeout": 5,
            "theme": "light"
        }

    def _load_meta_config(self):
        #Загрузка метаданных (путь к БД) из JSON файла.
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                data = json.load(f)
                # Путь к БД храним в атрибуте, а не в общем словаре настроек
                self.db_path = data.get("db_path", os.path.join(self.config_dir, "vault.db"))
        else:
            self.db_path = os.path.join(self.config_dir, "vault.db")
            self._save_meta_config()

    def _save_meta_config(self):
        #Сохранение метаданных (путь к БД) в JSON.
        with open(self.config_file, 'w') as f:
            json.dump({"db_path": self.db_path}, f, indent=4)

    def attach_database(self, db_helper: 'DatabaseHelper'):
        #Подключение к БД для синхронизации настроек.
        self._db_helper = db_helper
        self._load_settings_from_db()

    def _load_settings_from_db(self):
        #Загрузка настроек из таблицы settings (CFG-2).
        if not self._db_helper:
            return
        
        rows = self._db_helper.fetchall("SELECT setting_key, setting_value FROM settings")
        for row in rows:
            key, value = row
            # Преобразование строк из БД в нужные типы (int и т.д.) здесь опущено для простоты заглушки
            self.settings[key] = value

    def get(self, key: str, default=None):
        # Сначала ищем в runtime настройках, потом в БД
        return self.settings.get(key, default)

    def set(self, key: str, value: Any):
        self.settings[key] = value
        # Сохраняем в БД, если подключена (CFG-2)
        if self._db_helper:
            # Простая реализация upsert
            exists = self._db_helper.fetchone("SELECT 1 FROM settings WHERE setting_key = ?", (key,))
            if exists:
                self._db_helper.execute("UPDATE settings SET setting_value = ? WHERE setting_key = ?", (str(value), key))
            else:
                self._db_helper.execute("INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)", (key, str(value)))
