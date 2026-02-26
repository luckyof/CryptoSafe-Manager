import sqlite3
import threading
import os
import shutil
from typing import Optional

class DatabaseHelper:
    # Помощник для работы с SQLite. Потокобезопасный.
    # Требования: DB-1, DB-3, DB-4
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._initialize_db()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            # Включаем поддержку внешних ключей
            self._local.connection.execute("PRAGMA foreign_keys = ON")
        return self._local.connection

    def _initialize_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # 1. Таблица записей хранилища
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT,
                encrypted_password BLOB,
                url TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags TEXT
            )
        """)

        # 2. Журнал аудита (для Спринта 5)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                entry_id INTEGER,
                details TEXT,
                signature BLOB
            )
        """)

        # 3. Настройки
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT,
                encrypted INTEGER DEFAULT 0
            )
        """)

        # 4. Хранилище ключей (для Спринта 2)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT,
                salt BLOB,
                hash BLOB,
                params TEXT
            )
        """)
        
        #Создание индексов 
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_title ON vault_entries(title)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_username ON vault_entries(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        
        # Установка версии схемы
        cursor.execute("PRAGMA user_version = 1")
        
        conn.commit()

    def execute(self, query: str, params: tuple = ()):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor.lastrowid

    def fetchall(self, query: str, params: tuple = ()):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def fetchone(self, query: str, params: tuple = ()):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()

    #Механизм резервного копирования 
    def backup(self, backup_path: str) -> bool:
        """Создает копию файла базы данных."""
        try:
            # Закрываем текущее соединение для надежности копии
            if hasattr(self._local, 'connection'):
                self._local.connection.close()
                del self._local.connection
            
            if os.path.exists(self.db_path):
                shutil.copy2(self.db_path, backup_path)
                return True
            return False
        except Exception as e:
            print(f"Backup error: {e}")
            return False

    def restore(self, backup_path: str) -> bool:
        """Восстанавливает базу данных из файла (заглушка для Спринта 8)."""
        # Логика восстановления будет реализована в Спринте 8
        #проверяем наличие файла
        return os.path.exists(backup_path)

    def close(self):
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            del self._local.connection
