import tkinter as tk
from tkinter import ttk, messagebox
import os

# Импорт виджетов
from .widgets.secure_table import SecureTable
from .widgets.audit_log_viewer import AuditLogViewer
from .settings_dialog import SettingsDialog
from .setup_wizard import SetupWizard

# Импорт ядра и базы данных
from core.config import ConfigManager
from core.state_manager import state_manager
from core.events import event_bus
from core.audit import AuditManager
from database.db import DatabaseHelper
from core.key_manager import KeyManager

class MainWindow(tk.Tk):
    # ИСПРАВЛЕНО: переименовали аргумент, чтобы не конфликтовать с self.config()
    def __init__(self, config: ConfigManager):
        super().__init__()
        self.title("CryptoSafe Manager - Спринт 1")
        self.geometry("800x600")

        # ИСПРАВЛЕНО: сохраняем конфиг в переменную app_config, чтобы не затирать метод tk.Tk.config
        self.app_config = config
        self.db: DatabaseHelper = None
        self.audit: AuditManager = None

        self.create_menu()
        self.create_main_area()
        self.create_status_bar()
        
        # Запуск логики после инициализации окна
        self.after(100, self.startup_sequence)

    def startup_sequence(self):
        """Основная логика запуска: проверка БД, вход или настройка."""
        
        # Используем self.app_config
        db_path = self.app_config.db_path
        
        # Проверяем, существует ли файл базы данных
        if not os.path.exists(db_path):
            # Если БД нет -> Запуск мастера настройки
            self.run_setup_wizard()
        else:
            # Если БД есть -> Подключение
            self.login_and_load()

    def run_setup_wizard(self):
        """Запуск мастера первоначальной настройки."""
        # Передаем app_config
        wizard = SetupWizard(self, self.app_config)
        self.wait_window(wizard)
        
        if wizard.completed:
            # Создаем БД и сохраняем ключи
            self.initialize_new_vault(wizard.db_path, wizard.password)
            self.on_login_success()
            messagebox.showinfo("Успех", "Хранилище успешно создано и настроено!")
        else:
            # Если пользователь закрыл визард без завершения
            self.quit()

    def initialize_new_vault(self, db_path, password):
        """Создание новой БД и ключей."""
        # 1. Инициализируем БД (создаст файл и таблицы)
        self.db = DatabaseHelper(db_path)
        
        # 2. Генерируем ключи
        km = KeyManager()
        salt = km.generate_salt()
        
        # 3. Сохраняем соль в key_store
        self.db.execute("INSERT INTO key_store (key_type, salt) VALUES (?, ?)", ("master", salt))
        
        # 4. Обновляем конфигурацию
        self.app_config.db_path = db_path
        self.app_config.set("db_path", db_path) # Сохранит в JSON мета-файл
        self.app_config.attach_database(self.db)

    def login_and_load(self):
        """Подключение к существующей БД."""
        try:
            self.db = DatabaseHelper(self.app_config.db_path)
            self.app_config.attach_database(self.db)
            
            # Эмуляция входа
            state_manager.login("default_user")
            self.on_login_success()
        except Exception as e:
             messagebox.showerror("Ошибка", f"Не удалось открыть базу данных:\n{e}")
             self.quit()

    def on_login_success(self):
        """Действия после успешного входа."""
        # 1. Инициализируем Аудит
        self.audit = AuditManager(self.db)
        
        # 2. Обновляем статус бар
        self.status_label.config(text="Статус: Разблокировано")
        
        # 3. Генерируем событие входа
        event_bus.publish("UserLoggedIn", data={"user": "default_user"})
        
        # 4. Загружаем данные в таблицу
        self.load_entries()

    def load_entries(self):
        """Загрузка записей из БД в таблицу."""
        try:
            rows = self.db.fetchall("SELECT id, title, username, url FROM vault_entries")
            data = []
            for r in rows:
                data.append({"id": r[0], "title": r[1], "username": r[2], "url": r[3]})
            self.table.load_data(data)
        except Exception as e:
            print(f"Ошибка загрузки данных: {e}")

    # --- Методы создания интерфейса ---

    def create_menu(self):
        menubar = tk.Menu(self)
        
        # Меню "Файл"
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Новый сейф", command=self.stub_action)
        file_menu.add_command(label="Открыть...", command=self.stub_action)
        file_menu.add_command(label="Резервная копия", command=self.stub_action)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.quit)
        menubar.add_cascade(label="Файл", menu=file_menu)
        
        # Меню "Правка"
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить запись", command=self.stub_action)
        edit_menu.add_command(label="Изменить запись", command=self.stub_action)
        edit_menu.add_command(label="Удалить запись", command=self.stub_action)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        
        # Меню "Вид"
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи аудита", command=self.show_audit_window)
        view_menu.add_command(label="Настройки", command=self.show_settings)
        menubar.add_cascade(label="Вид", menu=view_menu)
        
        # Меню "Справка"
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.show_about)
        menubar.add_cascade(label="Справка", menu=help_menu)
        
        # ТЕПЕРЬ ЭТО РАБОТАЕТ: self.config - это метод tkinter, а не наш объект
        self.config(menu=menubar)

    def create_main_area(self):
        # Центральный виджет таблицы
        self.table = SecureTable(self)
        self.table.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def create_status_bar(self):
        self.status_bar = ttk.Frame(self)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_bar, text="Статус: Заблокировано", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.clipboard_label = ttk.Label(self.status_bar, text="Буфер: 00:00", relief=tk.SUNKEN)
        self.clipboard_label.pack(side=tk.RIGHT, fill=tk.X)

    # --- Действия меню ---
    
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
        messagebox.showinfo("О программе", "CryptoSafe Manager v0.1\nСпринт 1: Фундамент")

    def stub_action(self):
        messagebox.showinfo("Информация", "Функционал будет реализован в следующих спринтах.")
