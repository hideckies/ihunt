# Docs: https://pypi.org/project/duckduckgo-search/#description

from duckduckgo_search import DDGS
import json
from threading import Lock
from typing import Any
from ..models import Ihunt
from ..stdout import echo
from ..utils import create_prompt, extract_json_from_str, update_data_from_json


# Query: All
def req_duckduckgo(ihunt: Ihunt, lock: Lock, data_class: Any) -> None:
    echo("[*] Fetching DuckDuckGo...", ihunt.verbose)
    try:
        with lock:
            results = DDGS().chat(
                create_prompt(ihunt.query.value, data_class),
                model='claude-3-haiku',
                timeout=ihunt.timeout*2,
            )
            json_str = extract_json_from_str(results)
            if json_str is None:
                raise ValueError("JSON not found in the result.")
            update_data_from_json(ihunt.data, json.loads(json_str))
    except Exception as e:
         echo(f"[x] DuckDuckGo API error: {e}", ihunt.verbose)
    echo("[*] Finished fetching DuckDuckGo...", ihunt.verbose)

