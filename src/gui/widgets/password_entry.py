import tkinter as tk
from tkinter import ttk

class PasswordEntry(ttk.Frame):
    """
    Виджет для ввода пароля с возможностью отображения/скрытия текста.
    Требование: GUI-2
    """
    def __init__(self, parent, **kwargs):
        super().__init__(parent)
        
        self.show_var = tk.BooleanVar(value=True)
        
        # Поле ввода
        self.entry = ttk.Entry(self, show="*", **kwargs)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Кнопка показа
        self.toggle_btn = ttk.Button(self, text="👁", width=3, command=self.toggle_visibility)
        self.toggle_btn.pack(side=tk.RIGHT, padx=(5, 0))

    def toggle_visibility(self):
        if self.show_var.get():
            self.entry.config(show="")
            self.show_var.set(False)
        else:
            self.entry.config(show="*")
            self.show_var.set(True)

    def get(self):
        return self.entry.get()

    def set(self, value):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)
