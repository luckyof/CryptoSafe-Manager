import tkinter as tk
from tkinter import ttk

class SecureTable(ttk.Treeview):
    """
    Таблица для отображения записей хранилища.
    Требование: GUI-2
    """
    def __init__(self, parent, columns=("id", "title", "username", "url"), **kwargs):
        super().__init__(parent, columns=columns, show="headings", **kwargs)
        
        self.columns = columns
        # Настройка заголовков
        self.heading("id", text="ID")
        self.heading("title", text="Название")
        self.heading("username", text="Логин")
        self.heading("url", text="URL")
        
        # Настройка ширины столбцов
        self.column("id", width=30, stretch=False)
        self.column("title", width=150)
        self.column("username", width=150)
        self.column("url", width=200)

        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.yview)
        self.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def load_data(self, data):
        """Загрузка данных (список словарей)"""
        self.delete(*self.get_children())
        for item in data:
            self.insert("", tk.END, values=(item.get('id'), item.get('title'), 
                                            item.get('username'), item.get('url')))
