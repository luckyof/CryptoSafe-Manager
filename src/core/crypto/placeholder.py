
from .abstract import EncryptionService

class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes) -> bytes:
        # Используем ключ из key_manager
        key = self.key_manager.storage.get_key()
        if not key:
            raise ValueError("Key not set")
            
        # XOR Заглушка
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)