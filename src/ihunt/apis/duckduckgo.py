# Docs: https://pypi.org/project/duckduckgo-search/#description

from duckduckgo_search import DDGS
import json
from threading import Lock
from ..models import DataEmail, DataOrg, DataPerson, DataUrl, Ihunt
from ..stdout import echo
from ..utils import create_prompt, update_data_from_json


# Query: Email
# Return: Info
def req_duckduckgo_email(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching DuckDuckGo...", ihunt.verbose)
    try:
        with lock:
            results = DDGS().chat(create_prompt(ihunt.query.value, DataEmail), model='claude-3-haiku')
            update_data_from_json(ihunt.data, json.loads(results))
    except Exception as e:
         echo(f"[x] DuckDuckGo API error: {e}", ihunt.verbose)
    echo("[*] Finished fetching DuckDuckGo...", ihunt.verbose)


# Query: Org
# Return: info
def req_duckduckgo_org(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching DuckDuckGo...", ihunt.verbose)
    try:
        with lock:
            results = DDGS().chat(create_prompt(ihunt.query.value, DataOrg), model='claude-3-haiku')
            update_data_from_json(ihunt.data, json.loads(results))
    except Exception as e:
         echo(f"[x] DuckDuckGo API error: {e}", ihunt.verbose)
    echo("[*] Finished fetching DuckDuckGo...", ihunt.verbose)


# Query: Person
# Return: Info
def req_duckduckgo_person(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching DuckDuckGo...", ihunt.verbose)
    try:
        with lock:
            results = DDGS().chat(create_prompt(ihunt.query.value, DataPerson), model='claude-3-haiku')
            update_data_from_json(ihunt.data, json.loads(results))
    except Exception as e:
         echo(f"[x] DuckDuckGo API error: {e}", ihunt.verbose)
    echo("[*] Finished fetching DuckDuckGo...", ihunt.verbose)


# Query: URL
# Return: Info
def req_duckduckgo_url(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching DuckDuckGo...", ihunt.verbose)
    try:
        with lock:
            results = DDGS().chat(create_prompt(ihunt.query.value, DataUrl), model='claude-3-haiku')
            print(results)
            update_data_from_json(ihunt.data, json.loads(results))
    except Exception as e:
         echo(f"[x] DuckDuckGo API error: {e}", ihunt.verbose)
    echo("[*] Finished fetching DuckDuckGo...", ihunt.verbose)
