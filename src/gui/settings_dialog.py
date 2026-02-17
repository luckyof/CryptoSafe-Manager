import tkinter as tk
from tkinter import ttk

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Настройки")
        self.geometry("400x300")

        notebook = ttk.Notebook(self)

        # Вкладка Безопасность (заглушка)
        sec_frame = ttk.Frame(notebook)
        tk.Label(sec_frame, text="Таймаут буфера обмена (сек):").pack(pady=5)
        ttk.Entry(sec_frame).pack(fill=tk.X, padx=10)
        tk.Label(sec_frame, text="Авто-блокировка после неактивности (мин):").pack(pady=5)
        ttk.Entry(sec_frame).pack(fill=tk.X, padx=10)
        notebook.add(sec_frame, text="Безопасность")

        # Вкладка Внешний вид (заглушка)
        app_frame = ttk.Frame(notebook)
        tk.Label(app_frame, text="Тема:").pack(pady=5)
        ttk.Combobox(app_frame, values=["Светлая", "Темная"], state="readonly").pack(fill=tk.X, padx=10)
        tk.Label(app_frame, text="Язык:").pack(pady=5)
        ttk.Combobox(app_frame, values=["Русский", "English"], state="readonly").pack(fill=tk.X, padx=10)
        notebook.add(app_frame, text="Внешний вид")

        # Вкладка Дополнительно (заглушка)
        add_frame = ttk.Frame(notebook)
        tk.Label(add_frame, text="Резервное копирование:").pack(pady=5)
        ttk.Button(add_frame, text="Настроить (заглушка)").pack(padx=10)
        tk.Label(add_frame, text="Экспорт:").pack(pady=5)
        ttk.Button(add_frame, text="Настроить (заглушка)").pack(padx=10)
        notebook.add(add_frame, text="Дополнительно")

        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Button(self, text="Закрыть", command=self.destroy).pack(pady=10)