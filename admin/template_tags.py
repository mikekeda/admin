from __future__ import annotations

from typing import Dict, Optional


def get_item(dictionary: Dict[str, str], key) -> Optional[str]:
    return dictionary.get(key)


def any_in(keys: set[str], text: str) -> bool:
    return any(key in text for key in keys)
