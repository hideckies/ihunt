# Docs: https://eva.pingutil.com/

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://api.eva.pingutil.com/email"

# Query: Email
# Return: Verification
def req_eva_email(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching EVA...", ihunt.verbose)

    url = BASE_URL
    params = {
        "email": ihunt.query.value,
    }

    try:
        resp = requests.get(url, params=params)

        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if d["success"] != "success":
                    data = d["data"]
                    if ihunt.data.email is None:
                        ihunt.data.email = data["email_address"]
                    if ihunt.data.domain is None:
                        ihunt.data.domain = data["domain"]
                    if ihunt.data.gibberish is None:
                        ihunt.data.gibberish = data["gibberish"]
                    if ihunt.data.disposable is None:
                        ihunt.data.disposable = data["disposable"]
                    if ihunt.data.webmail is None:
                        ihunt.data.webmail = data["webmail"]
                    if ihunt.data.spam is None:
                        ihunt.data.spam = data["spam"]
                    return
    except Exception as e:
        echo(f"[x] EVA API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching EVA.", ihunt.verbose)