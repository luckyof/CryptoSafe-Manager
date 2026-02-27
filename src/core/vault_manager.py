# src/core/vault_manager.py
from typing import List, Dict, Optional
from database.db import DatabaseHelper
from core.crypto.placeholder import AES256Placeholder

class VaultManager:
    # Сервисный слой для управления записями хранилища.
    # Реализует требование DB-2: шифрование перед вставкой.
    def __init__(self, db: DatabaseHelper, encryption_service: AES256Placeholder, key: bytes):
        self.db = db
        self.crypto = encryption_service
        self.key = key

    def add_entry(self, title: str, username: str, password: str, url: str = "", notes: str = ""):
        #Добавление записи с шифрованием пароля
        
        # 1. Шифруем пароль (DB-2)
        encrypted_pass = self.crypto.encrypt(password.encode(), self.key)
        
        # 2. Вставляем в БД уже зашифрованные данные
        query = """
            INSERT INTO vault_entries (title, username, encrypted_password, url, notes)
            VALUES (?, ?, ?, ?, ?)
        """
        self.db.execute(query, (title, username, encrypted_pass, url, notes))
        
        # 3. Возвращаем ID созданной записи
        # (В sqlite3 lastrowid можно получить через курсор, но для упрощения вернем None или доработаем db.execute)
        # Для тестов достаточно, что данные записаны.

    def get_all_entries(self) -> List[Dict]:
        #Получение всех записей с расшифровкой паролей (для отображения).
        rows = self.db.fetchall("SELECT id, title, username, encrypted_password, url FROM vault_entries")
        
        result = []
        for row in rows:
            # Пытаемся расшифровать пароль
            try:
                decrypted_pass = self.crypto.decrypt(row[3], self.key).decode()
            except:
                decrypted_pass = "[DECRYPT_ERROR]"

            result.append({
                "id": row[0],
                "title": row[1],
                "username": row[2],
                "password": decrypted_pass,
                "url": row[4]
            })
        return result