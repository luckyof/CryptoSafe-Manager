import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from core.crypto.placeholder import AES256Placeholder
from core.events import EventBus, Event
from database.db import DatabaseHelper
@pytest.fixture
def temp_db(tmp_path):
    #Создает временную БД для тестов.
    db_file = tmp_path / "test.db"
    db = DatabaseHelper(str(db_file))
    yield db
    db.close()

@pytest.fixture
def crypto_service():
    return AES256Placeholder()

# TEST-1: Тесты шифрования
def test_encryption_placeholder(crypto_service):
    key = b'test_key_32_bytes_for_xor_cipher!!' # 32 bytes
    data = b'sensitive_data'
    
    encrypted = crypto_service.encrypt(data, key)
    assert encrypted != data
    
    decrypted = crypto_service.decrypt(encrypted, key)
    assert decrypted == data

# TEST-1: Тесты БД
def test_db_initialization(temp_db):
    # Проверяем создание таблиц
    res = temp_db.fetchone("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_entries'")
    assert res is not None
    
    res = temp_db.fetchone("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
    assert res is not None

def test_db_insert_and_fetch(temp_db):
    temp_db.execute(
        "INSERT INTO vault_entries (title, username) VALUES (?, ?)",
        ("Test Site", "user1")
    )
    row = temp_db.fetchone("SELECT * FROM vault_entries WHERE title = ?", ("Test Site",))
    assert row is not None
    assert row[1] == "Test Site"

# TEST-1: Тесты событий
def test_event_bus():
    bus = EventBus()
    called = []
    
    def callback(event: Event):
        called.append(event.name)
    
    bus.subscribe("TestEvent", callback)
    bus.publish("TestEvent", data={"test": 1})
    
    assert "TestEvent" in called
