# Docs: https://genderize.io/documentation

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://api.genderize.io"


# Query: Person
# Return: Gender
def req_genderize_person(ihunt: Ihunt, lock: Lock) -> None:
    url = BASE_URL
    params = {
        "name": ihunt.query.value,
    }

    try:
        resp = requests.get(url, params=params)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if ihunt.data.gender is None:
                    ihunt.data.gender = d["gender"]
    except Exception as e:
        echo(f"[x] Genderize API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching Genderize.", ihunt.verbose)
