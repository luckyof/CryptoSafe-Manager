from dataclasses import dataclass
from typing import Iterable, Iterator, Sequence, TypeVar

import tkinter as tk
from tkinter import ttk

T = TypeVar("T")


COMMON_SHORTCUTS = {
    "add_entry": "<Control-n>",
    "edit_entry": "<Control-e>",
    "delete_entry": "<Delete>",
    "copy_username": "<Control-u>",
    "copy_password": "<Control-c>",
    "toggle_password": "<Control-Shift-P>",
    "search": "<Control-f>",
    "lock": "<Control-l>",
    "settings": "<Control-comma>",
}


SECURITY_STATE_COLORS = {
    "locked": "#8a1f11",
    "unlocked": "#1f6f43",
    "warning": "#8a5a00",
    "neutral": "#3f4b5b",
}

THEMES = {
    "light": {
        "background": "#f4f5f7",
        "surface": "#ffffff",
        "text": "#1f2328",
        "muted": "#5b6470",
        "field": "#ffffff",
        "border": "#c9ced6",
        "selection": "#0b65c2",
        "selection_text": "#ffffff",
    },
    "dark": {
        "background": "#1f2328",
        "surface": "#2b3036",
        "text": "#f0f3f6",
        "muted": "#c6ccd3",
        "field": "#24292f",
        "border": "#555d66",
        "selection": "#2f81f7",
        "selection_text": "#ffffff",
    },
}


@dataclass(frozen=True)
class UserMessage:
    title: str
    body: str
    suggestion: str = ""

    def format(self) -> str:
        return f"{self.body}\n\n{self.suggestion}" if self.suggestion else self.body


class ToolTip:
    """Небольшая Tk-подсказка с метаданными для средств доступности."""

    def __init__(self, widget, text: str, delay_ms: int = 500):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id = None
        self._tip = None
        self._set_accessible_metadata(widget, text)
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<FocusIn>", self._schedule, add="+")
        widget.bind("<FocusOut>", self.hide, add="+")

    def _schedule(self, event=None):
        self.hide()
        self._after_id = self.widget.after(self.delay_ms, self.show)

    def show(self):
        if self._tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self._tip = tk.Toplevel(self.widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self._tip,
            text=self.text,
            justify=tk.LEFT,
            relief=tk.SOLID,
            borderwidth=1,
            padx=6,
            pady=3,
        )
        label.pack()

    def hide(self, event=None):
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None
        if self._tip:
            self._tip.destroy()
            self._tip = None

    @staticmethod
    def _set_accessible_metadata(widget, text: str):
        try:
            widget.configure(takefocus=True)
        except tk.TclError:
            pass
        setattr(widget, "accessible_name", text)


def security_state_color(state: str) -> str:
    return SECURITY_STATE_COLORS.get(state, SECURITY_STATE_COLORS["neutral"])


def normalize_theme(theme: str) -> str:
    value = str(theme or "light").strip().lower()
    if value in {"тёмная", "темная", "dark"}:
        return "dark"
    if value in {"светлая", "light"}:
        return "light"
    return "light"


def apply_theme(root, theme: str):
    theme_name = normalize_theme(theme)
    palette = THEMES[theme_name]
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(background=palette["background"])
    style.configure(".", background=palette["background"], foreground=palette["text"])
    style.configure("TFrame", background=palette["background"])
    style.configure("TLabelframe", background=palette["background"], foreground=palette["text"])
    style.configure("TLabelframe.Label", background=palette["background"], foreground=palette["text"])
    style.configure("TLabel", background=palette["background"], foreground=palette["text"])
    style.configure("TButton", background=palette["surface"], foreground=palette["text"])
    style.map(
        "TButton",
        background=[("active", palette["border"]), ("pressed", palette["border"])],
        foreground=[("disabled", palette["muted"])],
    )
    style.configure("TCheckbutton", background=palette["background"], foreground=palette["text"])
    style.configure("TRadiobutton", background=palette["background"], foreground=palette["text"])
    style.configure(
        "TEntry",
        background=palette["field"],
        fieldbackground=palette["field"],
        foreground=palette["text"],
        insertcolor=palette["text"],
    )
    style.configure(
        "TSpinbox",
        background=palette["field"],
        fieldbackground=palette["field"],
        foreground=palette["text"],
        arrowcolor=palette["text"],
    )
    style.map(
        "TSpinbox",
        fieldbackground=[("readonly", palette["field"]), ("disabled", palette["field"])],
        foreground=[("readonly", palette["text"]), ("disabled", palette["muted"])],
    )
    style.configure(
        "TCombobox",
        background=palette["field"],
        fieldbackground=palette["field"],
        foreground=palette["text"],
        arrowcolor=palette["text"],
        selectbackground=palette["selection"],
        selectforeground=palette["selection_text"],
    )
    style.map(
        "TCombobox",
        background=[("readonly", palette["field"]), ("disabled", palette["field"])],
        fieldbackground=[("readonly", palette["field"]), ("disabled", palette["field"])],
        foreground=[("readonly", palette["text"]), ("disabled", palette["muted"])],
        selectbackground=[("readonly", palette["field"])],
        selectforeground=[("readonly", palette["text"])],
        arrowcolor=[("readonly", palette["text"]), ("disabled", palette["muted"])],
    )
    root.option_add("*TCombobox*Listbox.background", palette["field"])
    root.option_add("*TCombobox*Listbox.foreground", palette["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", palette["selection"])
    root.option_add("*TCombobox*Listbox.selectForeground", palette["selection_text"])
    style.configure("TNotebook", background=palette["background"])
    style.configure("TNotebook.Tab", background=palette["surface"], foreground=palette["text"])
    style.map(
        "TNotebook.Tab",
        background=[("selected", palette["background"]), ("active", palette["border"])],
        foreground=[("selected", palette["text"])],
    )
    style.configure("Treeview", background=palette["surface"], fieldbackground=palette["surface"], foreground=palette["text"])
    style.configure("Treeview.Heading", background=palette["background"], foreground=palette["text"])
    style.map(
        "Treeview",
        background=[("selected", palette["selection"])],
        foreground=[("selected", palette["selection_text"])],
    )
    style.configure("SecurityLocked.TLabel", background=palette["background"])
    style.configure("SecurityUnlocked.TLabel", background=palette["background"])
    style.configure("SecurityWarning.TLabel", background=palette["background"])
    _apply_theme_to_children(root, palette)


def _apply_theme_to_children(widget, palette: dict):
    for child in widget.winfo_children():
        if isinstance(child, tk.Menu):
            continue
        options = {}
        for option, value in (("background", palette["background"]), ("foreground", palette["text"])):
            try:
                child.cget(option)
                options[option] = value
            except tk.TclError:
                pass
        if isinstance(child, tk.Canvas):
            options["background"] = palette["background"]
        if isinstance(child, (tk.Entry, tk.Text, tk.Listbox, tk.Spinbox)):
            options["background"] = palette["field"]
            options["foreground"] = palette["text"]
            options["insertbackground"] = palette["text"]
        if options:
            try:
                child.configure(**options)
            except tk.TclError:
                pass
        _apply_theme_to_children(child, palette)


def batched(items: Sequence[T], batch_size: int) -> Iterator[Sequence[T]]:
    size = max(1, int(batch_size or 1))
    for index in range(0, len(items), size):
        yield items[index : index + size]


def friendly_error_message(error: Exception, context: str = "operation") -> UserMessage:
    text = str(error).strip()
    lowered = text.lower()
    if "database" in lowered or "sqlite" in lowered or "locked" in lowered:
        return UserMessage(
            "Vault data is temporarily unavailable",
            f"CryptoSafe could not complete this {context} because the vault data is busy or unavailable.",
            "Close other CryptoSafe windows and try again. If this keeps happening, restart the app.",
        )
    if "permission" in lowered or "access" in lowered or "denied" in lowered:
        return UserMessage(
            "Permission needed",
            f"CryptoSafe does not have permission to complete this {context}.",
            "Choose a folder you can write to, or run the app with the required account permissions.",
        )
    if "password" in lowered or "authentication" in lowered or "decrypt" in lowered:
        return UserMessage(
            "Authentication required",
            f"CryptoSafe could not verify access for this {context}.",
            "Check the master password and try again.",
        )
    return UserMessage(
        "Action could not be completed",
        f"CryptoSafe could not complete this {context}.",
        "Try again. Technical details were written to the application log.",
    )
