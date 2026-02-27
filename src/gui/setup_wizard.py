import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .widgets.password_entry import PasswordEntry
from core.config import ConfigManager

class SetupWizard(tk.Toplevel):
    """
    Мастер первоначальной настройки.
    Требование: GUI-3
    """
    def __init__(self, parent, config: ConfigManager):
        super().__init__(parent)
        self.config = config
        self.title("Начальная настройка CryptoSafe")
        self.geometry("400x300")
        self.resizable(False, False)
        
        # Используем StringVar для привязки к полю ввода, но результат вернем как строку
        self.db_path_var = tk.StringVar(value=config.db_path)
        
        # Переменные для результатов
        self.db_path = None
        self.password = None
        self.completed = False
        
        self.create_widgets()
        
        self.transient(parent)
        self.grab_set()

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Вкладка 1: База данных
        tab_db = ttk.Frame(notebook, padding=10)
        notebook.add(tab_db, text="База данных")
        
        ttk.Label(tab_db, text="Расположение файла БД:").pack(anchor=tk.W)
        # Привязываем Entry к StringVar
        ttk.Entry(tab_db, textvariable=self.db_path_var).pack(fill=tk.X, pady=5)
        ttk.Button(tab_db, text="Обзор...", command=self.browse_db).pack(anchor=tk.W)
        
        # Вкладка 2: Мастер-пароль
        tab_pass = ttk.Frame(notebook, padding=10)
        notebook.add(tab_pass, text="Безопасность")
        
        ttk.Label(tab_pass, text="Создайте мастер-пароль:").pack(anchor=tk.W, pady=(0, 5))
        self.pass_entry = PasswordEntry(tab_pass)
        self.pass_entry.pack(fill=tk.X, pady=5)
        
        ttk.Label(tab_pass, text="Подтвердите пароль:").pack(anchor=tk.W, pady=(10, 5))
        self.pass_confirm = PasswordEntry(tab_pass)
        self.pass_confirm.pack(fill=tk.X, pady=5)
        
        # Вкладка 3: Настройки шифрования (Заглушка)
        tab_crypto = ttk.Frame(notebook, padding=10)
        notebook.add(tab_crypto, text="Шифрование")
        ttk.Label(tab_crypto, text="[STUB] Параметры формирования ключа будут доступны в Спринте 3.\n\nИспользуется: AES-256-GCM").pack(anchor=tk.W)

        # Кнопки
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=10, padx=10)
        ttk.Button(btn_frame, text="Готово", command=self.on_complete).pack(side=tk.RIGHT)

    def browse_db(self):
        path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("SQLite DB", "*.db")])
        if path:
            self.db_path_var.set(path)

    def on_complete(self):
        # ИСПРАВЛЕНО: Получаем значения из виджетов/переменных
        path = self.db_path_var.get() # Извлекаем строку из StringVar
        p1 = self.pass_entry.get()
        p2 = self.pass_confirm.get()

        # Валидация (требование SEC-2)
        if not path:
            messagebox.showerror("Ошибка", "Укажите путь к базе данных.")
            return
            
        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return
            
        if len(p1) < 8:
            messagebox.showwarning("Внимание", "Рекомендуется пароль длиной не менее 8 символов.")
        
        # Сохраняем результаты как обычные строки
        self.db_path = path
        self.password = p1
        
        self.completed = True
        self.destroy()
