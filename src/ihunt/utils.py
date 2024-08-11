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


# The function is used when stdout or write to the output file.
def remove_null_values_in_dict(data: dict[Any]) -> dict[Any]:
    return {
        k: remove_null_values_in_dict(v)
        if isinstance(v, dict)
        else v
        for k, v in data.items()
        if v is not None
    }