import pytest
import os
import sys
import shutil

# --- ВАЖНОЕ ИСПРАВЛЕНИЕ ПУТЕЙ ---
# Добавляем папку 'src' в пути, чтобы импорты работали так же, как в main.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from core.config import ConfigManager
from database.db import DatabaseHelper
from core.vault_manager import VaultManager
from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
from core.state_manager import state_manager

# --- FIXTURES ---

@pytest.fixture
def clean_env(tmp_path):
    """Создает чистое окружение для теста интеграции."""
    # 1. Путь к временной папке
    test_dir = tmp_path / "crypto_safe_test"
    test_dir.mkdir()
    
    # 2. Путь к БД
    db_path = test_dir / "vault.db"
    
    yield db_path
    
    # Очистка
    if os.path.exists(db_path):
        os.remove(db_path)

# --- TESTS ---

def test_full_setup_and_encryption_flow(clean_env):
    """
    TEST-2: Интеграционный тест полного цикла.
    Сценарий: Настройка БД -> Генерация ключа -> Добавление записи -> Проверка шифрования (DB-2).
    """
    db_path = str(clean_env)
    
    # 1. Инициализация БД (имитация Setup Wizard)
    db = DatabaseHelper(db_path)
    assert os.path.exists(db_path), "База данных не создана"
    
    # 2. Генерация ключа (имитация создания мастер-пароля)
    km = KeyManager()
    salt = km.generate_salt()
    master_key = km.derive_key("super_secret_password", salt)
    
    # Сохраняем соль в БД
    db.execute("INSERT INTO key_store (key_type, salt) VALUES (?, ?)", ("master", salt))
    
    # 3. Инициализация менеджера хранилища
    crypto = AES256Placeholder()
    vault = VaultManager(db, crypto, master_key)
    
    # 4. Добавление записи (Action)
    plain_password = "My_Secret_Pass_123"
    vault.add_entry("Google", "user@gmail.com", plain_password, "google.com")
    
    # 5. ПРОВЕРКА DB-2: Данные в БД должны быть зашифрованы
    # Делаем прямой запрос в БД, минуя VaultManager
    row = db.fetchone("SELECT encrypted_password FROM vault_entries WHERE title = 'Google'")
    
    assert row is not None, "Запись не найдена"
    stored_blob = row[0]
    
    # Проверка 1: Это байты (а не строка)
    assert isinstance(stored_blob, bytes)
    
    # Проверка 2: Это НЕ открытый текст (самое важное для DB-2)
    # Так как XOR обратим, мы проверяем, что строка не равна исходной.
    # Для реального AES это условие было бы строже (проверка формата).
    assert stored_blob != plain_password.encode(), "Пароль хранится в открытом виде!"
    
    # Проверка 3: Расшифровка работает корректно
    decrypted = crypto.decrypt(stored_blob, master_key).decode()
    assert decrypted == plain_password, "Ошибка расшифровки"
    
    db.close()

def test_config_loading(tmp_path):
    """
    TEST-2: Тест загрузки конфигурации.
    """
    # Создаем временный конфиг
    config_dir = tmp_path / ".cryptosafe"
    config_dir.mkdir()
    config_file = config_dir / "config_default.json"
    
    # Пишем тестовые данные
    import json
    with open(config_file, 'w') as f:
        json.dump({"db_path": str(tmp_path / "test.db")}, f)
    
    # Подменяем путь домашней директории (хитрость для тестов)
    from unittest.mock import patch
    with patch('os.path.expanduser', return_value=str(tmp_path)):
        cfg = ConfigManager()
        assert cfg.db_path == str(tmp_path / "test.db")