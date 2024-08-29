from dataclasses import fields
import ipaddress
import json
import re
from typing import Any


def is_empty(data: Any) -> bool:
    if data is None:
        return True
    if isinstance(data, list):
        if len(data) == 0:
            return True
        if all(elem == "" for elem in data):
            return True
    elif isinstance(data, dict):
        if not data:
            return True
    elif isinstance(data, str):
        if data == "":
            return True
    return False


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
Give me some information about "{query}". The output rules are below:

- Keep your answers concise.
- The output format is JSON.
- The output is only JSON.
- All values are strings.
- Skip for unknown items, or write empty string "".
- Create list for multiple values.
- Do not use code block.
- The keys of the JSON: {", ".join(get_class_field_names(data_class))}
"""


# The function is used for extracting JSON object from results of LLM APIs.
def extract_json_from_str(text: str) -> str|None:
    json_pattern = re.compile(r'\{.*?\}', re.DOTALL)
    json_strs = json_pattern.findall(text)
    if len(json_strs) == 0:
        return None
    # Find JSON string
    for json_str in json_strs:
        try:
            _ = json.loads(json_str)
            return json_str
        except json.JSONDecodeError:
            continue


# Update Data from given JSON object
def update_data_from_json(data: object, json_obj: dict[str, Any]) -> object:
    for field in fields(data):
        current_value = getattr(data, field.name)
        if field.name in json_obj and is_empty(current_value):
            setattr(data, field.name, json_obj[field.name])


# The function is used when stdout or write to the output file.
def remove_null_values_in_dict(data: dict[Any]) -> dict[Any]:
    new_dict: dict[Any] = {}
    for k, v in data.items():
        if is_empty(v):
            continue
        if isinstance(v, list):
            if len(v) == 0:
                continue
            # Remove empty values
            v = [item for item in v if item != ""]
            # Make unique list (delete duplicates)
            v = list(set(v))
        new_dict[k] = v
    return new_dict
