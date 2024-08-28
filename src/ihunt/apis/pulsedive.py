# Docs: https://pulsedive.com/api/

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://ipapi.co"


# Query: IP
# Return: Info
def req_ipapi_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching IPAPI...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}/json/"

    try:
        resp = requests.get(url, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if ihunt.data.ip is None:
                    ihunt.data.ip = d["ip"]
    except Exception as e:
        echo(f"[x] IPAPI API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching IPAPI.", ihunt.verbose)
