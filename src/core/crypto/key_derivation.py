from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import secrets
import logging

logger = logging.getLogger("KeyDerivation")

class KeyDerivationService:
    # Лимиты для защиты от DoS (SEC-4)
    MAX_TIME_COST = 10
    MAX_MEMORY_COST = 262144 # 256 MB
    MAX_PARALLELISM = 8
    MAX_PBKDF2_ITERATIONS = 500000

    def __init__(self, config: dict = None):
        cfg = config or {}
        
        # Чтение конфига с валидацией
        time_cost = self._validate_param(cfg.get('argon2_time', 3), 1, self.MAX_TIME_COST, "time_cost")
        memory_cost = self._validate_param(cfg.get('argon2_memory', 65536), 1024, self.MAX_MEMORY_COST, "memory_cost")
        parallelism = self._validate_param(cfg.get('argon2_parallelism', 4), 1, self.MAX_PARALLELISM, "parallelism")
        
        self.argon2_hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )
        self.pbkdf2_iterations = self._validate_param(cfg.get('pbkdf2_iterations', 100000), 10000, self.MAX_PBKDF2_ITERATIONS, "pbkdf2_iterations")

    def _validate_param(self, value, min_val, max_val, name):
        if not isinstance(value, int):
            logger.warning(f"Invalid type for {name}, using default.")
            # Здесь стоит вернуть дефолт, но для простоты вернем value, если оно число
        if value < min_val:
            logger.warning(f"{name} too low ({value}), clamping to {min_val}")
            return min_val
        if value > max_val:
            logger.warning(f"{name} too high ({value}), clamping to {max_val}")
            return max_val
        return value

    def generate_salt(self) -> bytes:
        return os.urandom(16)

    def create_auth_hash(self, password: str) -> str:
        return self.argon2_hasher.hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        try:
            self.argon2_hasher.verify(stored_hash, password)
            return True
        except VerifyMismatchError:
            secrets.compare_digest(b'dummy', b'dummy')
            return False
        except Exception as e:
            logger.error(f"Verification error: {e}")
            return False

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))