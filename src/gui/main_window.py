import tkinter as tk
from tkinter import ttk, messagebox
import os
import logging

# Виджеты
from .widgets.secure_table import SecureTable
from .widgets.audit_log_viewer import AuditLogViewer
from .settings_dialog import SettingsDialog
from .setup_wizard import SetupWizard
from .dialogs.login_dialog import LoginDialog
from .dialogs.change_password_dialog import ChangePasswordDialog

# Ядро
from core.config import ConfigManager
from core.state_manager import state_manager
from core.events import event_bus
from core.audit import AuditManager
from database.db import DatabaseHelper
from core.key_manager import KeyManager
from core.vault_manager import VaultManager
from core.crypto.placeholder import AES256Placeholder

logger = logging.getLogger("MainWindow")

class MainWindow(tk.Tk):
    def __init__(self, config: ConfigManager):
        super().__init__()
        self.title("CryptoSafe Manager - Sprint 2")
        self.geometry("800x600")

        self.app_config = config
        self.db = None
        self.audit = None
        self.key_manager = None
        self.encryption_service = None
        self.vault_manager = None

        # UI
        self.create_menu()
        self.create_main_area()
        self.create_status_bar()
        
        # Логика запуска
        self.after(100, self.startup_sequence)
        
        # --- CACHE-2, AUTH-4: Автоблокировка ---
        self.auto_lock_check_interval = 60000 # 1 минута
        self.after(self.auto_lock_check_interval, self.check_inactivity)
        
        # --- CACHE-4: Очистка при выходе ---
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # --- ЗАПУСК И ИНИЦИАЛИЗАЦИЯ ---

    def startup_sequence(self):
        db_path = self.app_config.db_path
        
        if not os.path.exists(db_path):
            self.run_setup_wizard()
        else:
            self.login_and_load()

    def run_setup_wizard(self):
        wizard = SetupWizard(self, self.app_config)
        self.wait_window(wizard)
        
        if wizard.completed:
            if self.initialize_new_vault(wizard.db_path, wizard.password):
                self.on_login_success()
                messagebox.showinfo("Успех", "Хранилище успешно создано!", parent=self)
            else:
                messagebox.showerror("Ошибка", "Не удалось создать хранилище.", parent=self)
                self.quit()
        else:
            self.quit()

    def initialize_new_vault(self, db_path, password):
        try:
            self.db = DatabaseHelper(db_path)
            self.app_config.db_path = db_path
            self.app_config.set("db_path", db_path) 
            self.app_config.attach_database(self.db)

            # KeyManager
            self.key_manager = KeyManager(self.db)
            if not self.key_manager.setup_new_vault(password):
                return False
            
            # Crypto Service
            self.encryption_service = AES256Placeholder()
            self.encryption_service.set_key_manager(self.key_manager)
            
            # VaultManager (ARC-2)
            self.vault_manager = VaultManager(self.db, self.encryption_service)
            
            return True
        except Exception as e:
            logger.error(f"Init error: {e}")
            return False

    def login_and_load(self):
        try:
            self.db = DatabaseHelper(self.app_config.db_path)
            self.app_config.attach_database(self.db)
            
            self.key_manager = KeyManager(self.db)
            self.encryption_service = AES256Placeholder()
            self.encryption_service.set_key_manager(self.key_manager)
            
            # VaultManager создаем до входа, он понадобится для смены пароля
            self.vault_manager = VaultManager(self.db, self.encryption_service)
            
            login = LoginDialog(self, self.key_manager)
            
            if login.success:
                state_manager.login("default_user")
                self.on_login_success()
            else:
                self.quit()
        except Exception as e:
             logger.error(f"Load error: {e}")
             messagebox.showerror("Ошибка", f"Не удалось открыть БД:\n{e}")
             self.quit()

    def on_login_success(self):
        self.audit = AuditManager(self.db)
        self.status_label.config(text="Статус: Разблокировано")
        event_bus.publish("UserLoggedIn", data={"user": "default_user"})
        self.load_entries()

    def load_entries(self):
        try:
            # Используем VaultManager
            data = self.vault_manager.get_all_entries()
            self.table.load_data(data)
        except Exception as e:
            logger.error(f"Load entries error: {e}")

    # --- БЕЗОПАСНОСТЬ И БЛОКИРОВКА ---

    def check_inactivity(self):
        """CACHE-2: Проверка простоя."""
        if not state_manager.is_locked:
            timeout = self.app_config.get("auto_lock_timeout", 5) # минут
            if state_manager.check_inactivity(timeout):
                self.lock_application()
        
        self.after(self.auto_lock_check_interval, self.check_inactivity)

    def lock_application(self):
        """Блокировка хранилища."""
        logger.info("Locking application...")
        self.key_manager.lock()
        state_manager.logout()
        
        self.status_label.config(text="Статус: ЗАБЛОКИРОВАНО")
        self.table.load_data([]) # Очистка UI
        
        # Запрос пароля для разблокировки
        login = LoginDialog(self, self.key_manager)
        if login.success:
            state_manager.login("default_user")
            self.on_login_success()
        else:
            self.on_close()

    def on_close(self):
        """CACHE-4: Завершение работы."""
        logger.info("Closing application...")
        if self.key_manager:
            self.key_manager.lock()
        self.destroy()

    # --- ИНТЕРФЕЙС (UI) ---

    def create_menu(self):
        menubar = tk.Menu(self)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Заблокировать", command=self.lock_application)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_close)
        menubar.add_cascade(label="Файл", menu=file_menu)
        
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить запись (Stub)", command=self.stub_action)
        edit_menu.add_separator()
        edit_menu.add_command(label="Сменить мастер-пароль", command=self.show_change_password)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи аудита", command=self.show_audit_window)
        view_menu.add_command(label="Настройки", command=self.show_settings)
        menubar.add_cascade(label="Вид", menu=view_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.show_about)
        menubar.add_cascade(label="Справка", menu=help_menu)
        
        self.config(menu=menubar)

    def create_main_area(self):
        self.table = SecureTable(self)
        self.table.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Привязка событий активности (AUTH-4)
        self.bind_all("<Button-1>", lambda e: state_manager.update_activity())
        self.bind_all("<Key>", lambda e: state_manager.update_activity())

    def create_status_bar(self):
        self.status_bar = ttk.Frame(self)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_bar, text="Статус: Заблокировано", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.clipboard_label = ttk.Label(self.status_bar, text="Буфер: --", relief=tk.SUNKEN)
        self.clipboard_label.pack(side=tk.RIGHT, fill=tk.X)

    # --- ОБРАБОТЧИКИ МЕНЮ ---

    def show_change_password(self):
        ChangePasswordDialog(self, self.key_manager, self.vault_manager, self.encryption_service)

    def show_settings(self):
        SettingsDialog(self)

    def show_audit_window(self):
        win = tk.Toplevel(self)
        win.title("Журнал аудита")
        win.geometry("500x300")
        viewer = AuditLogViewer(win)
        viewer.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        if self.db:
            logs = self.db.fetchall("SELECT timestamp, action, details FROM audit_log ORDER BY timestamp DESC")
            for log in logs:
                viewer.log(f"{log[0]} - {log[1]}: {log[2]}")

    def show_about(self):
        messagebox.showinfo("О программе", "CryptoSafe Manager v0.2\nSprint 2: Security Hardening")

    def stub_action(self):
        messagebox.showinfo("Информация", "Функционал будет реализован в следующих спринтах.")