from __future__ import annotations


def any_in(keys: set[str], text: str) -> bool:
    return any(key in text for key in keys)
