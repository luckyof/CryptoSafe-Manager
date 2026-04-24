import logging
import os
import shutil
import sqlite3
import threading

logger = logging.getLogger("Database")

DB_SCHEMA_VERSION = 3


class DatabaseHelper:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._initialize_db()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "connection"):
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

        cursor.execute("PRAGMA user_version")
        version = cursor.fetchone()[0]

        self._create_supporting_tables(cursor)

        if self._table_exists(cursor, "vault_entries"):
            if self._vault_entries_needs_migration(cursor):
                self._migrate_vault_entries(cursor)
        else:
            self._create_vault_entries_table(cursor)

        self._create_indexes(cursor)

        if version < DB_SCHEMA_VERSION:
            cursor.execute(f"PRAGMA user_version = {DB_SCHEMA_VERSION}")

        conn.commit()

    def _create_supporting_tables(self, cursor):
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                entry_id INTEGER,
                details TEXT,
                signature BLOB
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT,
                encrypted INTEGER DEFAULT 0
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT UNIQUE NOT NULL,
                key_data BLOB,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

    def _create_vault_entries_table(self, cursor):
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                tags TEXT
            )
            """
        )

    def _create_indexes(self, cursor):
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_created_at ON vault_entries(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_updated_at ON vault_entries(updated_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_tags ON vault_entries(tags)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key)")

    @staticmethod
    def _table_exists(cursor, table_name: str) -> bool:
        cursor.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        )
        return cursor.fetchone()[0] > 0

    def _vault_entries_needs_migration(self, cursor) -> bool:
        cursor.execute("PRAGMA table_info(vault_entries)")
        columns = {row[1] for row in cursor.fetchall()}
        clean_columns = {"id", "encrypted_data", "created_at", "updated_at", "tags"}
        return columns != clean_columns

    def _migrate_vault_entries(self, cursor):
        logger.info("Migrating vault_entries to clean Sprint 3 schema")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_entries_new (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                tags TEXT
            )
            """
        )

        cursor.execute("PRAGMA table_info(vault_entries)")
        columns = {row[1] for row in cursor.fetchall()}

        if "encrypted_data" in columns:
            cursor.execute(
                """
                INSERT INTO vault_entries_new (id, encrypted_data, created_at, updated_at, tags)
                SELECT
                    CAST(id AS TEXT),
                    encrypted_data,
                    COALESCE(created_at, CURRENT_TIMESTAMP),
                    COALESCE(updated_at, CURRENT_TIMESTAMP),
                    COALESCE(tags, '[]')
                FROM vault_entries
                WHERE encrypted_data IS NOT NULL
                """
            )

        cursor.execute("DROP TABLE IF EXISTS vault_entries_old")
        cursor.execute("ALTER TABLE vault_entries RENAME TO vault_entries_old")
        cursor.execute("ALTER TABLE vault_entries_new RENAME TO vault_entries")

    def execute(self, query: str, params: tuple = ()):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        if not getattr(self._local, "explicit_transaction", False):
            conn.commit()
        return cursor.lastrowid

    def execute_many(self, queries: list):
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
        conn = self._get_connection()
        self._local.explicit_transaction = True
        conn.execute("BEGIN IMMEDIATE")

    def commit_transaction(self):
        conn = self._get_connection()
        conn.commit()
        self._local.explicit_transaction = False

    def rollback_transaction(self):
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
            if hasattr(self._local, "connection"):
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
        if hasattr(self._local, "connection"):
            self._local.connection.close()
            del self._local.connection
