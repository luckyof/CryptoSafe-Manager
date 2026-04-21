"""
Search Widget — виджет поиска с real-time фильтрацией.
Реализует требования SEARCH-1 — SEARCH-2:
  SEARCH-1: Full-text search, fuzzy matching, field-specific filters
  SEARCH-2: Real-time обновление при вводе
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional, List, Dict, Any


class SearchWidget(ttk.Frame):
    """
    Виджет поиска записей с real-time фильтрацией.
    """

    def __init__(self, parent, on_search: Optional[Callable] = None, **kwargs):
        super().__init__(parent, **kwargs)

        self.on_search_callback = on_search
        self._search_history: List[str] = []
        self._max_history = 10  # SEARCH-4

        # Поле поиска
        search_frame = ttk.Frame(self)
        search_frame.pack(fill=tk.X, padx=5, pady=5)

        # Иконка поиска
        ttk.Label(search_frame, text="🔍").pack(side=tk.LEFT, padx=(0, 5))

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Placeholder
        self.search_entry.insert(0, "Поиск (название, логин, URL, заметки...)")
        self.search_entry.bind("<FocusIn>", self._on_focus_in)
        self.search_entry.bind("<FocusOut>", self._on_focus_out)

        # SEARCH-2: Real-time поиск при вводе
        self.search_var.trace_add("write", self._on_search_changed)

        # Кнопка очистки
        clear_btn = ttk.Button(search_frame, text="✕", width=3, command=self.clear)
        clear_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Кнопка истории
        self.history_btn = ttk.Button(search_frame, text="📋", width=3, command=self._show_history)
        self.history_btn.pack(side=tk.RIGHT, padx=(0, 5))
        self.history_btn.pack_forget()  # Скрыта пока нет истории

        # Фильтры (SEARCH-3)
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Label(filter_frame, text="Фильтр:").pack(side=tk.LEFT, padx=(0, 5))

        self.category_var = tk.StringVar(value="Все")
        self.category_combo = ttk.Combobox(filter_frame, textvariable=self.category_var,
                                            width=15, state="readonly")
        self.category_combo['values'] = ["Все", "Работа", "Личное", "Финансы", "Соцсети", "Другое"]
        self.category_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.category_combo.bind("<<ComboboxSelected>>", self._on_filter_changed)

    def _on_focus_in(self, event):
        """Убрать placeholder при фокусе."""
        current = self.search_var.get()
        if current == "Поиск (название, логин, URL, заметки...)":
            self.search_var.set("")

    def _on_focus_out(self, event):
        """Восстановить placeholder если пусто."""
        current = self.search_var.get()
        if not current:
            self.search_var.set("Поиск (название, логин, URL, заметки...)")

    def _on_search_changed(self, *args):
        """SEARCH-2: Real-time обновление при вводе."""
        query = self.search_var.get().strip()
        if query and query != "Поиск (название, логин, URL, заметки...)":
            # Добавляем в историю (SEARCH-4)
            if query not in self._search_history:
                self._search_history.append(query)
                if len(self._search_history) > self._max_history:
                    self._search_history.pop(0)
                self.history_btn.pack(side=tk.RIGHT, padx=(0, 5))

            # Вызываем callback
            if self.on_search_callback:
                self.on_search_callback(query)

    def _on_filter_changed(self, event=None):
        """SEARCH-3: Обработчик изменения фильтра."""
        query = self.search_var.get().strip()
        category = self.category_var.get()

        if self.on_search_callback:
            # Формируем комбинированный запрос
            if category != "Все":
                combined = f'category:"{category}" {query}' if query else f'category:"{category}"'
            else:
                combined = query

            self.on_search_callback(combined if combined else "")

    def _show_history(self):
        """SEARCH-4: Показать историю поиска."""
        if not self._search_history:
            return

        popup = tk.Toplevel(self)
        popup.title("История поиска")
        popup.geometry("300x200")
        popup.transient(self.winfo_toplevel())

        listbox = tk.Listbox(popup)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for item in reversed(self._search_history):
            listbox.insert(tk.END, item)

        listbox.bind("<Double-1>", lambda e: self._select_history(listbox, popup))

    def _select_history(self, listbox: tk.Listbox, popup: tk.Toplevel):
        """Выбрать запрос из истории."""
        selection = listbox.curselection()
        if selection:
            query = listbox.get(selection[0])
            self.search_var.set(query)
            popup.destroy()

    def clear(self):
        """Очистить поле поиска."""
        self.search_var.set("")
        self.category_var.set("Все")
        if self.on_search_callback:
            self.on_search_callback("")

    def get_query(self) -> str:
        """Получить текущий поисковый запрос."""
        return self.search_var.get().strip()

    def set_categories(self, categories: List[str]):
        """Установить список категорий для фильтра."""
        values = ["Все"] + categories
        self.category_combo['values'] = values
