import tkinter as tk
from tkinter import ttk

class PasswordEntry(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.showing = False

        self.entry = ttk.Entry(self, show="*")
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.toggle_btn = ttk.Button(self, text="Показать", command=self.toggle_visibility, width=8)
        self.toggle_btn.pack(side=tk.RIGHT)

    def toggle_visibility(self):
        self.showing = not self.showing
        self.entry.config(show="" if self.showing else "*")
        self.toggle_btn.config(text="Скрыть" if self.showing else "Показать")

    def get(self):
        return self.entry.get()

    def insert(self, index, value):
        self.entry.insert(index, value)