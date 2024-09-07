# Docs: https://pulsedive.com/api/

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "Pulsedive"
BASE_URL = "https://pulsedive.com/api"

# Query: Domain
# Return: Info
def req_pulsedive_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/info.php"
    params = {
        "indicator": "pulsedive.com",
        "pretty": "1",
        "key": ihunt.apikeys.pulsedive,
    }

    try:
        resp = requests.get(url, params=params, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if is_empty(ihunt.data.ports):
                    ihunt.data.ports = d["attributes"]["port"]
                if is_empty(ihunt.data.protocols):
                    ihunt.data.protocols = d["attributes"]["protocol"]
                if is_empty(ihunt.data.technologies):
                    ihunt.data.technologies = d["attributes"]["technology"]
                if is_empty(ihunt.data.http_headers):
                    ihunt.data.http_headers = d["properties"]["http"]
                if is_empty(ihunt.data.dns):
                    ihunt.data.dns = d["properties"]["dns"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)


# Query: IP
# Return: Info
def req_pulsedive_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/info.php"
    params = {
        "indicator": "pulsedive.com",
        "pretty": "1",
        "key": ihunt.apikeys.pulsedive,
    }

    try:
        resp = requests.get(url, params=params, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if is_empty(ihunt.data.ip):
                    ihunt.data.ip = d["ip"]
                if is_empty(ihunt.data.ports):
                    ihunt.data.ports = d["attributes"]["port"]
                if is_empty(ihunt.data.protocols):
                    ihunt.data.protocols = d["attributes"]["protocol"]
                if is_empty(ihunt.data.technologies):
                    ihunt.data.technologies = d["attributes"]["technology"]
                if is_empty(ihunt.data.http_headers):
                    ihunt.data.http_headers = d["properties"]["http"]
                if is_empty(ihunt.data.dns):
                    ihunt.data.dns = d["properties"]["dns"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)