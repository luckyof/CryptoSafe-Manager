import json
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional


class PasswordManagerFormatHandler:
    format_name = "password_manager_json"

    def serialize_bitwarden(self, entries: Iterable[Dict], include_fields: Optional[List[str]] = None) -> bytes:
        selected = set(include_fields or [])
        items = []
        for entry in entries:
            login = {}
            if not selected or "username" in selected:
                login["username"] = entry.get("username", "")
            if not selected or "password" in selected:
                login["password"] = entry.get("password", "")
            if not selected or "url" in selected:
                login["uris"] = [{"uri": entry.get("url", "")}] if entry.get("url") else []

            item = {
                "type": 1,
                "name": entry.get("title", ""),
                "login": login,
                "notes": entry.get("notes", "") if (not selected or "notes" in selected) else "",
                "folderId": entry.get("category", "") or None,
            }
            items.append(item)

        payload = {
            "encrypted": False,
            "source": "CryptoSafe Manager",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "items": items,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")

    def serialize_lastpass_json(self, entries: Iterable[Dict], include_fields: Optional[List[str]] = None) -> bytes:
        selected = set(include_fields or [])
        rows = []
        for entry in entries:
            rows.append(
                {
                    "name": entry.get("title", ""),
                    "username": entry.get("username", "") if (not selected or "username" in selected) else "",
                    "password": entry.get("password", "") if (not selected or "password" in selected) else "",
                    "url": entry.get("url", "") if (not selected or "url" in selected) else "",
                    "extra": entry.get("notes", "") if (not selected or "notes" in selected) else "",
                    "grouping": entry.get("category", ""),
                }
            )
        return json.dumps(rows, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
