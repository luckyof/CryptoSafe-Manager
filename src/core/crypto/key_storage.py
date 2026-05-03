
import ctypes
import logging
import sys

logger = logging.getLogger("KeyStorage")

class SecureMemoryCache:
    """
    Безопасное хранение ключа в памяти.
    Реализует требования CACHE-1, CACHE-3, CACHE-4, SEC-2.
    """
    def __init__(self):
        self._key = None
        self._locked = False
        self._page_size = 4096  # Стандартный размер страницы

    def store_key(self, key: bytes):
        """Сохраняет ключ в памяти с блокировкой страниц."""
        if self._key:
            self.clear_key()
        self._key = bytearray(key)
        # CACHE-3: Блокировка памяти (mlock/VirtualLock)
        self._lock_memory()

    def get_key(self) -> bytes:
        """Возвращает копию ключа."""
        if self._key:
            return bytes(self._key)
        return None

    def clear_key(self):
        """Безопасная очистка памяти (CACHE-4)."""
        if self._key:
            self._unlock_memory()
            self._secure_zero_memory(self._key)
            self._key = None
            logger.info("Encryption key cleared from memory.")

    def _secure_zero_memory(self, buffer: bytearray):
        """
        Безопасное обнуление буфера.
        Использует ctypes для гарантированной записи в память.
        """
        if buffer:
            try:
                # Получаем указатель на данные внутри bytearray
                ptr = (ctypes.c_char * len(buffer)).from_buffer(buffer)
                ctypes.memset(ptr, 0, len(buffer))
            except (TypeError, ValueError, OSError):
                # Fallback: перезапись через срез
                for i in range(len(buffer)):
                    buffer[i] = 0

    def _lock_memory(self):
        if not self._key or self._locked:
            return

        try:
            if sys.platform == 'win32':
                # Windows: VirtualLock
                kernel32 = ctypes.windll.kernel32
                # Получаем текущий процесс
                h_process = kernel32.GetCurrentProcess()
                # Выравниваем размер до границы страницы
                size = ((len(self._key) + self._page_size - 1) // self._page_size) * self._page_size
                # Блокируем память
                result = kernel32.VirtualLock(ctypes.c_void_p(id(self._key)), size)
                if result:
                    self._locked = True
                    logger.debug("Memory locked using VirtualLock (Windows)")
                else:
                    logger.warning("VirtualLock failed, continuing without memory protection")
            else:
                # Unix/Linux/macOS: mlock
                libc = ctypes.CDLL('libc.so.6' if sys.platform.startswith('linux') else None)
                # Выравниваем размер до границы страницы
                size = ((len(self._key) + self._page_size - 1) // self._page_size) * self._page_size
                result = libc.mlock(ctypes.c_void_p(id(self._key)), size)
                if result == 0:
                    self._locked = True
                    logger.debug("Memory locked using mlock (Unix)")
                else:
                    logger.warning("mlock failed, continuing without memory protection")
        except (OSError, AttributeError, ctypes.ArgumentError) as e:
            logger.warning(f"Memory locking not available: {e}")

    def _unlock_memory(self):
        if not self._key or not self._locked:
            return

        try:
            if sys.platform == 'win32':
                kernel32 = ctypes.windll.kernel32
                size = ((len(self._key) + self._page_size - 1) // self._page_size) * self._page_size
                kernel32.VirtualUnlock(ctypes.c_void_p(id(self._key)), size)
            else:
                libc = ctypes.CDLL('libc.so.6' if sys.platform.startswith('linux') else None)
                size = ((len(self._key) + self._page_size - 1) // self._page_size) * self._page_size
                libc.munlock(ctypes.c_void_p(id(self._key)), size)
            self._locked = False
        except (OSError, AttributeError, ctypes.ArgumentError):
            pass  # Игнорируем ошибки при разблокировке