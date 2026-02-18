from .abstract import EncryptionService

class AES256Placeholder(EncryptionService):
    
    #Заглушка сервиса шифрования. Использует простой XOR для демонстрации.
    #В Спринте 3 будет заменен на реальный AES-256-GCM.
    #Требование: CRY-2

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        # Простой XOR: data ^ key (циклично)
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        # Для XOR расшифровка идентична шифрованию
        return self.encrypt(ciphertext, key)
