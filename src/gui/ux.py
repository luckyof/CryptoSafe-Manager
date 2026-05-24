from dataclasses import dataclass
from typing import Iterable, Iterator, Sequence, TypeVar

import tkinter as tk

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
