from typing import Dict, Optional


def get_item(dictionary: Dict[str, str], key) -> Optional[str]:
    return dictionary.get(key)
