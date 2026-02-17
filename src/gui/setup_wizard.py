import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from .widgets.password_entry import PasswordEntry

class SetupWizard(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Мастер первоначальной настройки")
        self.geometry("400x300")
        self.parent = parent

        tk.Label(self, text="Создайте мастер-пароль:").pack(pady=5)
        self.pass1 = PasswordEntry(self)
        self.pass1.pack(fill=tk.X, padx=10)

        tk.Label(self, text="Подтвердите пароль:").pack(pady=5)
        self.pass2 = PasswordEntry(self)
        self.pass2.pack(fill=tk.X, padx=10)

        tk.Label(self, text="Выберите расположение базы данных:").pack(pady=5)
        self.db_path_var = tk.StringVar()
        db_frame = ttk.Frame(self)
        db_frame.pack(fill=tk.X, padx=10)
        ttk.Entry(db_frame, textvariable=self.db_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(db_frame, text="Обзор", command=self.browse_db).pack(side=tk.RIGHT)

        tk.Label(self, text="Настройки шифрования (заглушка для параметров формирования ключа):").pack(pady=5)
        self.enc_settings = ttk.Entry(self)
        self.enc_settings.pack(fill=tk.X, padx=10)

        ttk.Button(self, text="Завершить", command=self.finish_setup).pack(pady=10)

    def browse_db(self):
        path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("SQLite DB", "*.db")])
        if path:
            self.db_path_var.set(path)

    def finish_setup(self):
        if self.pass1.get() != self.pass2.get():
            messagebox.showerror("Ошибка", "Пароли не совпадают!")
            return
        # Здесь сохраните настройки (заглушка: интеграция с config.py в будущем)
        messagebox.showinfo("Успех", "Настройка завершена. Мастер-пароль и путь к БД сохранены (заглушка).")
        self.destroy()