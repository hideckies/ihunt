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
- Skip for unknown items, or write empty string "".
- Create list for multiple values.
- Do not use code block.
- The keys of the JSON: {", ".join(get_class_field_names(data_class))}
"""


# Update Data from given JSON object
def update_data_from_json(data: object, json_obj: dict[str, Any]) -> object:
    for field in fields(data):
        current_value = getattr(data, field.name)
        if field.name in json_obj and current_value is None:
            setattr(data, field.name, json_obj[field.name])


# The function is used when stdout or write to the output file.
def remove_null_values_in_dict(data: dict[Any]) -> dict[Any]:
    new_dict: dict[Any] = {}
    for k, v in data.items():
        if isinstance(v, list):
            if len(v) == 0:
                continue
            # Remove empty values
            v = [item for item in v if item != ""]
            # Make unique list (delete duplicates)
            v = list(set(v))
        else:
            if v is None or v == '':
                continue
        new_dict[k] = v
    return new_dict
