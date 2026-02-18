from abc import ABC, abstractmethod

class EncryptionService(ABC):
    #Абстрактный интерфейс для сервисов шифрования.
    #Требование: CRY-1
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Зашифровать данные."""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Расшифровать данные."""
        pass
