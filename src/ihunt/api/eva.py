# Docs: https://eva.pingutil.com/

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "EVA"
BASE_URL = "https://api.eva.pingutil.com/email"

# Query: Email
# Return: Verification
def req_eva_email(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL
    params = {
        "email": ihunt.query.value,
    }

    try:
        resp = requests.get(url, params=params, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if d["success"] != "success":
                    data = d["data"]
                    if is_empty(ihunt.data.email):
                        ihunt.data.email = data["email_address"]
                    if is_empty(ihunt.data.domain):
                        ihunt.data.domain = data["domain"]
                    if is_empty(ihunt.data.gibberish):
                        ihunt.data.gibberish = data["gibberish"]
                    if is_empty(ihunt.data.disposable):
                        ihunt.data.disposable = data["disposable"]
                    if is_empty(ihunt.data.webmail):
                        ihunt.data.webmail = data["webmail"]
                    if is_empty(ihunt.data.spam):
                        ihunt.data.spam = data["spam"]
                    return
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)