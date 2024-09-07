# Docs: https://www.robtex.com/api/

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "Robtex"
BASE_URL = "https://freeapi.robtex.com/ipquery"


# Query: IP
# Return: Info
def req_robtex_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}"

    try:
        resp = requests.get(url, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if d["status"] != "ok":
                    return
                if is_empty(ihunt.data.city):
                    ihunt.data.city = d["city"]
                if is_empty(ihunt.data.country_name):
                    ihunt.data.country_name = d["country"]
                if is_empty(ihunt.data.asn):
                    ihunt.data.asn = d["as"]
                if is_empty(ihunt.data.asname):
                    ihunt.data.asname = d["asname"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}...", ihunt.verbose)
        