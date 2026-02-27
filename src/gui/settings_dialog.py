import tkinter as tk
from tkinter import ttk

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Настройки")
        self.geometry("450x350")
        
        self.create_widgets()
        
        self.transient(parent)
        self.grab_set()

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Вкладка "Безопасность"
        tab_security = ttk.Frame(notebook, padding=10)
        notebook.add(tab_security, text="Безопасность")
        
        ttk.Label(tab_security, text="Таймаут буфера обмена (сек):").pack(anchor=tk.W)
        ttk.Spinbox(tab_security, from_=10, to=300).pack(anchor=tk.W, pady=5)
        
        ttk.Label(tab_security, text="Авто-блокировка (мин):").pack(anchor=tk.W, pady=(10, 0))
        ttk.Spinbox(tab_security, from_=1, to=60).pack(anchor=tk.W, pady=5)
        
        # Вкладка "Внешний вид"
        tab_appearance = ttk.Frame(notebook, padding=10)
        notebook.add(tab_appearance, text="Внешний вид")
        
        ttk.Label(tab_appearance, text="Тема:").pack(anchor=tk.W)
        ttk.Combobox(tab_appearance, values=["System Default", "Light", "Dark"]).pack(anchor=tk.W, pady=5)
        
        # Вкладка "Дополнительно"
        tab_advanced = ttk.Frame(notebook, padding=10)
        notebook.add(tab_advanced, text="Дополнительно")
        
        ttk.Label(tab_advanced, text="[STUB] Настройки резервного копирования и экспорта.").pack(anchor=tk.W)

        # Кнопка закрытия
        ttk.Button(self, text="Закрыть", command=self.destroy).pack(pady=10)
