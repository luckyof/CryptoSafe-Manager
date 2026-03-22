from typing import List, Dict
from database.db import DatabaseHelper
from core.crypto.abstract import EncryptionService

class VaultManager:
    def __init__(self, db: DatabaseHelper, encryption_service: EncryptionService):
        self.db = db
        self.crypto = encryption_service

    def add_entry(self, title: str, username: str, password: str, url: str = "", notes: str = ""):
        # ARC-2: Шифрование через сервис, ключ берется из KeyManager внутри
        encrypted_pass = self.crypto.encrypt(password.encode())
        
        query = """
            INSERT INTO vault_entries (title, username, encrypted_password, url, notes)
            VALUES (?, ?, ?, ?, ?)
        """
        self.db.execute(query, (title, username, encrypted_pass, url, notes))

    def get_all_entries(self) -> List[Dict]:
        rows = self.db.fetchall("SELECT id, title, username, encrypted_password, url FROM vault_entries")
        result = []
        for row in rows:
            try:
                decrypted_pass = self.crypto.decrypt(row[3]).decode()
            except Exception:
                decrypted_pass = "[DECRYPT_ERROR]"

            result.append({
                "id": row[0],
                "title": row[1],
                "username": row[2],
                "password": decrypted_pass,
                "url": row[4]
            })
        return result
    
    def get_all_entries_raw(self) -> List[Dict]:
        """Получение записей без расшифровки (для смены пароля)."""
        rows = self.db.fetchall("SELECT id, encrypted_password FROM vault_entries")
        return [{"id": r[0], "enc_data": r[1]} for r in rows]
    
    def update_entry_password(self, entry_id: int, new_encrypted_data: bytes):
        self.db.execute("UPDATE vault_entries SET encrypted_password = ? WHERE id = ?", 
                        (new_encrypted_data, entry_id))