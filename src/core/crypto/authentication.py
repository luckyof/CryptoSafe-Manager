import re
import time
import logging
from typing import Tuple

logger = logging.getLogger("Authentication")

COMMON_PASSWORDS = {"password", "123456", "qwerty", "password123", "admin", "123456789"}
LOCKOUT_WINDOW_SECONDS = 900 # 15 минут для сброса счетчика

class AuthenticationService:
    def __init__(self):
        self.failed_attempts = 0
        self.last_failed_time = 0

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        if len(password) < 12:
            return False, "Минимальная длина пароля: 12 символов."
        
        if password.lower() in COMMON_PASSWORDS:
            return False, "Пароль слишком распространен."

        checks = [
            (r'[A-Z]', "заглавными буквами"),
            (r'[a-z]', "строчными буквами"),
            (r'[0-9]', "цифрами"),
            (r'[^A-Za-z0-9]', "специальными символами")
        ]
        
        missing = []
        for pattern, name in checks:
            if not re.search(pattern, password):
                missing.append(name)
        
        if missing:
            return False, f"Пароль должен содержать: {', '.join(missing)}."
            
        return True, "Пароль надежный."

    def get_backoff_delay(self) -> float:
        if self.failed_attempts >= 5:
            return 30.0
        elif self.failed_attempts >= 3:
            return 5.0
        elif self.failed_attempts >= 1:
            return 1.0
        return 0.0

    def register_failed_attempt(self):
        self.failed_attempts += 1
        self.last_failed_time = time.time()
        logger.info(f"Failed attempt #{self.failed_attempts}")

    def reset_attempts(self):
        self.failed_attempts = 0
        self.last_failed_time = 0

    def is_locked_out(self) -> bool:
        # Сброс счетчика после долгого перерыва
        if self.failed_attempts > 0 and (time.time() - self.last_failed_time > LOCKOUT_WINDOW_SECONDS):
            self.reset_attempts()
            return False

        delay = self.get_backoff_delay()
        if delay > 0 and (time.time() - self.last_failed_time < delay):
            return True
        return False

    def get_remaining_lockout_time(self) -> int:
        delay = self.get_backoff_delay()
        elapsed = time.time() - self.last_failed_time
        return max(0, int(delay - elapsed))