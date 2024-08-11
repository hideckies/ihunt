import ipaddress
from typing import Any


def is_ip_address(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except:
        return False


def has_duplicate(arr: list[Any]) -> bool:
    return len(arr) != len(set(arr))