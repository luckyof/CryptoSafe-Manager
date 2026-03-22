# src/core/crypto/key_storage.py
import ctypes
import logging

logger = logging.getLogger("KeyStorage")

class SecureMemoryCache:
    """
    Безопасное хранение ключа в памяти.
    Реализует требования CACHE-1, CACHE-4, SEC-2.
    """
    def __init__(self):
        self._key = None

    def store_key(self, key: bytes):
        """Сохраняет ключ в памяти."""
        if self._key:
            self.clear_key()
        self._key = bytearray(key)
        # CACHE-3: Попытка блокировки памяти (mlock) - оставляем как есть
        self._lock_memory()

    def get_key(self) -> bytes:
        """Возвращает копию ключа."""
        if self._key:
            return bytes(self._key)
        return None

    def clear_key(self):
        """Безопасная очистка памяти (CACHE-4)."""
        if self._key:
            self._secure_zero_memory(self._key)
            self._key = None
            logger.info("Encryption key cleared from memory.")

    def _secure_zero_memory(self, buffer: bytearray):
        """
        Безопасное обнуление буфера.
        ИСПРАВЛЕНО: Использование ctypes.memset(id(buffer)) было фатальной ошибкой,
        так как затирало заголовок объекта Python, а не данные.
        Правильный способ в Python - перезапись через срез.
        """
        if buffer:
            # Метод 1: Pythonic way (безопасно, достаточно быстро)
            # Перезаписываем каждый байт нулем
            for i in range(len(buffer)):
                buffer[i] = 0
            
            # Метод 2: ctypes (более низкоуровневый, но безопасный для данных)
            # Используем ctypes.c_char.from_buffer, чтобы добраться до реальных данных
            # Раскомментируй блок ниже, если хочешь использовать ctypes (чуть быстрее для огромных буферов)
            """
            try:
                # Получаем указатель на данные внутри bytearray
                ptr = (ctypes.c_char * len(buffer)).from_buffer(buffer)
                ctypes.memset(ptr, 0, len(buffer))
            except (TypeError, ValueError):
                # Fallback, если буфер не доступен для записи (маловероятно для bytearray)
                for i in range(len(buffer)):
                    buffer[i] = 0
            """

    def _lock_memory(self):
        # Заглушка для mlock. Реализация зависит от ОС.
        # Для desktop приложения можно не реализовывать строго в учебном проекте.
        pass