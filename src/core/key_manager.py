import logging
from typing import TYPE_CHECKING
from .crypto.key_derivation import KeyDerivationService
from .crypto.key_storage import SecureMemoryCache
from .crypto.authentication import AuthenticationService

if TYPE_CHECKING:
    from src.database.db import DatabaseHelper
    from src.core.vault_manager import VaultManager

logger = logging.getLogger("KeyManager")

class KeyManager:
    def __init__(self, db_helper: 'DatabaseHelper', config: dict = None):
        self.db = db_helper
        self.config = config or {}
        self.derivation = KeyDerivationService(self.config)
        self.storage = SecureMemoryCache()
        self.auth = AuthenticationService()

    def setup_new_vault(self, password: str) -> bool:
        try:
            auth_hash = self.derivation.create_auth_hash(password)
            enc_salt = self.derivation.generate_salt()
            
            self.db.execute("DELETE FROM key_store") 
            self.db.execute(
                "INSERT INTO key_store (key_type, key_data) VALUES (?, ?)", 
                ("auth_hash", auth_hash.encode('utf-8'))
            )
            self.db.execute(
                "INSERT INTO key_store (key_type, key_data) VALUES (?, ?)", 
                ("enc_salt", enc_salt)
            )
            
            enc_key = self.derivation.derive_encryption_key(password, enc_salt)
            self.storage.store_key(enc_key)
            logger.info("Vault setup complete.")
            return True
        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False

    def unlock(self, password: str) -> bool:
        if self.auth.is_locked_out():
            raise PermissionError(f"Blocked. Wait {self.auth.get_remaining_lockout_time()}s.")

        row_hash = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'auth_hash'")
        row_salt = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'enc_salt'")
        
        if not row_hash or not row_salt:
            logger.error("Keys not found in DB.")
            return False
            
        stored_hash = row_hash[0].decode('utf-8')
        enc_salt = row_salt[0]

        if self.derivation.verify_password(password, stored_hash):
            self.auth.reset_attempts()
            enc_key = self.derivation.derive_encryption_key(password, enc_salt)
            self.storage.store_key(enc_key)
            logger.info("Vault unlocked.")
            return True
        else:
            self.auth.register_failed_attempt()
            return False

    def lock(self):
        self.storage.clear_key()
        logger.info("Vault locked.")

    #СМЕНА ПАРОЛЯ 

    def change_password(self, old_password: str, new_password: str, vault_manager: 'VaultManager', crypto_service) -> bool:
        # 1. Проверка старого пароля
        if not self.unlock(old_password):
            raise ValueError("Неверный текущий пароль.")

        # 2. Валидация нового
        valid, msg = self.auth.validate_password_strength(new_password)
        if not valid:
            raise ValueError(msg)

        # Сохраняем старые ключи для отката
        old_auth_hash = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'auth_hash'")[0]
        old_enc_salt = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'enc_salt'")[0]
        old_key_bytes = self.storage.get_key()

        try:
            # 3. Получаем все данные
            raw_entries = vault_manager.get_all_entries_raw()

            # 4. Генерируем новые ключи
            new_auth_hash = self.derivation.create_auth_hash(new_password)
            new_enc_salt = self.derivation.generate_salt()
            new_enc_key = self.derivation.derive_encryption_key(new_password, new_enc_salt)

            # 5. Перешифровка
            re_encrypted_data = []

            # Трюк: создаем временный сервис для шифрования новым ключом
            temp_crypto = type(crypto_service)()
            temp_storage = SecureMemoryCache()
            temp_storage.store_key(new_enc_key)
            temp_crypto.set_key_manager(type('FakeKM', (), {'storage': temp_storage})())

            for entry in raw_entries:
                # Расшифровываем старым (текущим в self.storage)
                decrypted_bytes = crypto_service.decrypt(entry['enc_data'])
                # Шифруем новым
                new_cipher = temp_crypto.encrypt(decrypted_bytes)
                re_encrypted_data.append((entry['id'], new_cipher))

                # Немедленная очистка расшифрованных данных из памяти
                del decrypted_bytes

            # 6. Атомарное обновление БД (CHANGE-4)
            queries = []

            # Обновляем данные записей
            for eid, new_ciph in re_encrypted_data:
                queries.append((
                    "UPDATE vault_entries SET encrypted_password = ? WHERE id = ?",
                    (new_ciph, eid)
                ))

            # Обновляем ключи
            queries.append((
                "UPDATE key_store SET key_data = ? WHERE key_type = 'auth_hash'",
                (new_auth_hash.encode('utf-8'),)
            ))
            queries.append((
                "UPDATE key_store SET key_data = ? WHERE key_type = 'enc_salt'",
                (new_enc_salt,)
            ))

            # Выполняем все запросы в транзакции
            self.db.begin_transaction()
            try:
                for query, params in queries:
                    self.db.execute(query, params)
                self.db.commit_transaction()
            except Exception as db_error:
                self.db.rollback_transaction()
                raise RuntimeError(f"DB transaction failed: {db_error}")

            # 7. Обновляем ключ в оперативной памяти
            self.storage.store_key(new_enc_key)

            logger.info("Password changed successfully.")
            return True

        except Exception as e:
            logger.error(f"Password change failed: {e}")
            # Откат: восстанавливаем старые ключи в памяти
            if old_key_bytes:
                self.storage.store_key(old_key_bytes)
            raise RuntimeError(f"Ошибка при смене пароля: {e}")