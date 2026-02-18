import secrets
import hashlib

class KeyManager:
    def derive_key(self, password: str, salt: bytes) -> bytes:
        
        #В реальной реализации буду использовать Argon2.
        #Сейчас простая заглушка на SHA-256.
     
        #Только для тестов структуры.
        return hashlib.sha256(salt + password.encode()).digest()

    def generate_salt(self) -> bytes:
        return secrets.token_bytes(16)

    def store_key(self, key: bytes):
        #заглушка для Спринта 2
        pass

    def load_key(self) -> bytes:
        #заглушка для Спринта 2
        return b''
