import tkinter as tk
from tkinter import ttk

class SecureTable(ttk.Treeview):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, columns=("title", "username", "url", "notes"), show="headings", **kwargs)
        
        self.heading("title", text="Название")
        self.heading("username", text="Имя пользователя")
        self.heading("url", text="URL")
        self.heading("notes", text="Заметки")
        
        self.column("title", width=200)
        self.column("username", width=150)
        self.column("url", width=200)
        self.column("notes", width=200)

        # Тестовые данные (заглушка)
        self.insert("", tk.END, values=("Тестовая запись 1", "user1", "https://example.com", "Заметка 1"))
        self.insert("", tk.END, values=("Тестовая запись 2", "user2", "https://example.org", "Заметка 2"))