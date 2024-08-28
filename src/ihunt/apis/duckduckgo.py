# Docs: https://pypi.org/project/duckduckgo-search/#description

from duckduckgo_search import DDGS
import json
from threading import Lock
from typing import Any
from ..models import DataEmail, DataIp, DataOrg, DataPerson, DataUrl, Ihunt
from ..stdout import echo
from ..utils import create_prompt, update_data_from_json


# Query: Email, IP, Org, Person, URL
def req_duckduckgo(ihunt: Ihunt, lock: Lock, data_class: Any) -> None:
    echo("[*] Fetching DuckDuckGo...", ihunt.verbose)
    try:
        with lock:
            results = DDGS().chat(
                create_prompt(ihunt.query.value, data_class),
                model='claude-3-haiku',
                timeout=ihunt.timeout*2,
            )
            update_data_from_json(ihunt.data, json.loads(results))
    except Exception as e:
         echo(f"[x] DuckDuckGo API error: {e}", ihunt.verbose)
    echo("[*] Finished fetching DuckDuckGo...", ihunt.verbose)

