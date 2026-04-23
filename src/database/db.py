
import sqlite3
import threading
import os
import shutil
from typing import Optional
import logging

logger = logging.getLogger("Database")

class DatabaseHelper:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._initialize_db()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.connection.execute("PRAGMA foreign_keys = ON")
            self._local.connection.execute("PRAGMA journal_mode = WAL")
            self._local.connection.execute("PRAGMA synchronous = NORMAL")
            self._local.connection.execute("PRAGMA temp_store = MEMORY")
            self._local.connection.execute("PRAGMA cache_size = -20000")
            self._local.explicit_transaction = False
        return self._local.connection

    def _initialize_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Проверка версии для миграции (простая реализация для спринта)
        cursor.execute("PRAGMA user_version")
        version = cursor.fetchone()[0]

        # 1. Таблица записей хранилища (ОБНОВЛЕНО ДЛЯ СПРИНТА 3 - DATA-1, DB-1)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB,
                title TEXT,
                username TEXT,
                encrypted_password BLOB,
                url TEXT,
                notes TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                tags TEXT
            )
        """)

        # Добавляем колонку encrypted_data если её нет (миграция со Спринта 2)
        try:
            cursor.execute("ALTER TABLE vault_entries ADD COLUMN encrypted_data BLOB")
        except Exception:
            pass  # Колонка уже существует

        # Индексы (DB-1)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_created_at ON vault_entries(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_updated_at ON vault_entries(updated_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_tags ON vault_entries(tags)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_title ON vault_entries(title)")

        # 2. Журнал аудита
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

        # 4. Хранилище ключей (ОБНОВЛЕНО ДЛЯ СПРИНТА 2 - DB-1)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT UNIQUE NOT NULL,
                key_data BLOB,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Индексы
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_title ON vault_entries(title)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key)")
        
        # Установка версии схемы (для будущих миграций)
        if version < 3:
            cursor.execute("PRAGMA user_version = 3")
        
        conn.commit()

    def execute(self, query: str, params: tuple = ()):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        if not getattr(self._local, 'explicit_transaction', False):
            conn.commit()
        return cursor.lastrowid

    def execute_many(self, queries: list):
        """
        Выполнение нескольких запросов в одной транзакции.
        CHANGE-4: Атомарное обновление БД.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            for query, params in queries:
                cursor.execute(query, params if params else ())
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Transaction failed, rolled back: {e}")
            return False

    def begin_transaction(self):
        """Начало транзакции."""
        conn = self._get_connection()
        self._local.explicit_transaction = True
        conn.execute("BEGIN IMMEDIATE")

    def commit_transaction(self):
        """Фиксация транзакции."""
        conn = self._get_connection()
        conn.commit()
        self._local.explicit_transaction = False

    def rollback_transaction(self):
        """Откат транзакции."""
        conn = self._get_connection()
        conn.rollback()
        self._local.explicit_transaction = False
        logger.warning("Transaction rolled back")

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

    def backup(self, backup_path: str) -> bool:
        try:
            if hasattr(self._local, 'connection'):
                self._local.connection.close()
                del self._local.connection
            
            if os.path.exists(self.db_path):
                shutil.copy2(self.db_path, backup_path)
                return True
            return False
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return False

    def close(self):
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            del self._local.connection
