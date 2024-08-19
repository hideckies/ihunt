from dataclasses import fields
import ipaddress
import json
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


# Get field names from dataclass.
def get_class_field_names(Any) -> list[str]:
    return [field.name for field in fields(Any)]


# The function is used for creating prompt for AI-related APIs.
def create_prompt(query: str, data_class: Any) -> str:
    return f"""
Give me some information about the email address "{query}". The rules are below:

- Keep your answers concise.
- The output format is JSON.
- Do not use commas for number values.
- Skip for unknown items.
- Do not use code block.
- The keys of the JSON: {", ".join(get_class_field_names(data_class))}
"""


# Update Data from given JSON object
def update_data_from_json(data: object, json_obj: dict[str, Any]) -> object:
    for field in fields(data):
        current_value = getattr(data, field.name)
        if field.name in json_obj and current_value is None:
            setattr(data, field.name, json_obj[field.name])
