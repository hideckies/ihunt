# Docs: https://www.robtex.com/api/

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://freeapi.robtex.com/ipquery"


# Query: IP
# Return: Info
def req_robtex_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching Robtex...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}"

    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if d["status"] != "ok":
                    return
                if ihunt.data.city is None:
                    ihunt.data.city = d["city"]
                if ihunt.data.country_name is None:
                    ihunt.data.country_name = d["country"]
                if ihunt.data.asn is None:
                    ihunt.data.asn = d["as"]
                if ihunt.data.asname is None:
                    ihunt.data.asname = d["asname"]
    except Exception as e:
        echo(f"[x] Robtex API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching Robtex...", ihunt.verbose)
        