"""
GUI 1-4
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Dict, Any, Set


class SecureTable(ttk.Treeview):
    """Table for displaying vault entries."""

    def __init__(self, parent, **kwargs):
        columns = ("title", "username", "password", "toggle", "url", "updated_at", "category")
        super().__init__(parent, columns=columns, show="headings", **kwargs)

        self._visible_password_ids: Set[str] = set()
        self._entries_data: Dict[str, Dict[str, Any]] = {}
        self._on_entry_selected_callback = None
        self._on_context_action_callback = None

        self.heading("title", text="Название", command=lambda: self._sort_by_column("title"))
        self.heading("username", text="Логин", command=lambda: self._sort_by_column("username"))
        self.heading("password", text="Пароль", command=lambda: self._sort_by_column("password"))
        self.heading("toggle", text="", command=lambda: None)
        self.heading("url", text="Сайт", command=lambda: self._sort_by_column("url"))
        self.heading("updated_at", text="Изменён", command=lambda: self._sort_by_column("updated_at"))
        self.heading("category", text="Категория", command=lambda: self._sort_by_column("category"))

        self.column("title", width=200, minwidth=100)
        self.column("username", width=150, minwidth=80)
        self.column("password", width=160, minwidth=120)
        self.column("toggle", width=56, minwidth=48, stretch=False, anchor=tk.CENTER)
        self.column("url", width=180, minwidth=100)
        self.column("updated_at", width=120, minwidth=80, stretch=False)
        self.column("category", width=100, minwidth=60)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.yview)
        self.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Открыть", command=self._on_open)
        self.context_menu.add_command(label="Редактировать", command=self._on_edit)
        self.context_menu.add_command(label="Копировать пароль", command=self._on_copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Удалить", command=self._on_delete)
        self.context_menu.add_command(label="Удалить навсегда", command=self._on_permanent_delete)

        self.bind("<Button-1>", self._on_left_click, add="+")
        self.bind("<Button-3>", self._show_context_menu)
        self.bind("<Double-1>", self._on_double_click)

    def load_data(self, data: List[Dict[str, Any]]):
        """Load entry data into the table."""
        self.delete(*self.get_children())
        self._entries_data.clear()

        valid_ids = {item.get("id", "") for item in data if item.get("id", "")}
        self._visible_password_ids.intersection_update(valid_ids)

        for item in data:
            entry_id = item.get("id", "")
            self._entries_data[entry_id] = item

            username = self._mask_username(item.get("username", ""))
            password = self._format_password(entry_id, item.get("password", ""))
            toggle = self._toggle_icon(entry_id)
            url_display = self._extract_domain(item.get("url", ""))
            updated_at = self._format_date(item.get("updated_at", ""))

            self.insert(
                "",
                tk.END,
                iid=entry_id,
                values=(
                    item.get("title", ""),
                    username,
                    password,
                    toggle,
                    url_display,
                    updated_at,
                    item.get("category", ""),
                ),
            )

    def get_selected_entries(self) -> List[Dict[str, Any]]:
        """Return selected entry payloads."""
        selected_iids = self.selection()
        return [self._entries_data.get(iid, {}) for iid in selected_iids if iid in self._entries_data]

    def get_selected_ids(self) -> List[str]:
        """Return selected entry ids."""
        return list(self.selection())

    def toggle_password_visibility(self):
        """Toggle password visibility for selected rows."""
        selected_ids = self.get_selected_ids()
        if not selected_ids:
            return False

        hidden_exists = any(entry_id not in self._visible_password_ids for entry_id in selected_ids)
        if hidden_exists:
            self._visible_password_ids.update(selected_ids)
        else:
            for entry_id in selected_ids:
                self._visible_password_ids.discard(entry_id)

        self._refresh_password_column()
        return any(entry_id in self._visible_password_ids for entry_id in selected_ids)

    def passwords_visible(self) -> bool:
        """Return whether any selected password is currently shown."""
        selected_ids = self.get_selected_ids()
        return any(entry_id in self._visible_password_ids for entry_id in selected_ids)

    def set_selection_callback(self, callback: Callable):
        """Set selection callback."""
        self._on_entry_selected_callback = callback
        self.bind("<<TreeviewSelect>>", self._on_select)

    def set_context_callback(self, callback: Callable):
        """Set context action callback."""
        self._on_context_action_callback = callback

    def _mask_username(self, username: str) -> str:
        if not username:
            return ""
        if len(username) <= 4:
            return username
        return username[:4] + "•" * min(len(username) - 4, 10)

    def _is_password_visible_for_entry(self, entry_id: str) -> bool:
        return entry_id in self._visible_password_ids

    def _format_password(self, entry_id: str, password: str) -> str:
        if not password:
            return ""
        if self._is_password_visible_for_entry(entry_id):
            return password
        return "•" * min(max(len(password), 8), 12)

    def _toggle_icon(self, entry_id: str) -> str:
        return "🙈" if self._is_password_visible_for_entry(entry_id) else "👁"

    def _refresh_password_column(self):
        for item_id in self.get_children():
            entry = self._entries_data.get(item_id, {})
            self.set(item_id, "password", self._format_password(item_id, entry.get("password", "")))
            self.set(item_id, "toggle", self._toggle_icon(item_id))

    def _toggle_entry_password_visibility(self, entry_id: str):
        if not entry_id or entry_id not in self._entries_data:
            return

        if entry_id in self._visible_password_ids:
            self._visible_password_ids.remove(entry_id)
        else:
            self._visible_password_ids.add(entry_id)

        entry = self._entries_data.get(entry_id, {})
        self.set(entry_id, "password", self._format_password(entry_id, entry.get("password", "")))
        self.set(entry_id, "toggle", self._toggle_icon(entry_id))

    @staticmethod
    def _extract_domain(url: str) -> str:
        if not url:
            return ""
        domain = url.split("://")[-1] if "://" in url else url
        domain = domain.split("/")[0]
        domain = domain.split(":")[0]
        return domain if len(domain) <= 30 else domain[:27] + "..."

    @staticmethod
    def _format_date(date_str: str) -> str:
        if not date_str:
            return ""
        if "T" in date_str:
            return date_str.replace("T", " ")[:16]
        return date_str[:16] if len(date_str) > 16 else date_str

    def _sort_by_column(self, column: str):
        items = [(self.set(k, column), k) for k in self.get_children()]
        items.sort(key=lambda x: x[0].lower() if isinstance(x[0], str) else x[0])

        reverse = getattr(self, f"_sort_reverse_{column}", False)
        items.reverse() if reverse else items
        setattr(self, f"_sort_reverse_{column}", not reverse)

        for index, (_, iid) in enumerate(items):
            self.move(iid, "", index)

    def _show_context_menu(self, event):
        item = self.identify_row(event.y)
        if item:
            self.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _on_left_click(self, event):
        row_id = self.identify_row(event.y)
        column_id = self.identify_column(event.x)
        if row_id and column_id == "#4":
            self.selection_set(row_id)
            self._toggle_entry_password_visibility(row_id)
            return "break"
        return None

    def _on_open(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("open", selected[0])

    def _on_edit(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("edit", selected[0])

    def _on_copy_password(self):
        selected = self.get_selected_entries()
        if selected:
            password = selected[0].get("password", "")
            if password:
                self.clipboard_clear()
                self.clipboard_append(password)

    def _on_delete(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("delete", selected[0])

    def _on_permanent_delete(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("permanent_delete", selected[0])

    def _on_double_click(self, event):
        row_id = self.identify_row(event.y)
        column_id = self.identify_column(event.x)
        if row_id and column_id == "#4":
            return "break"
        if row_id:
            self.selection_set(row_id)
            self._on_open()
        return None

    def _on_select(self, event):
        if self._on_entry_selected_callback:
            selected = self.get_selected_entries()
            if selected:
                self._on_entry_selected_callback(selected[0])
