# Docs: https://docs.sublime.security/reference/emailrep-introduction

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "Emailrep"
BASE_URL = "https://emailrep.io"


# TODO: The API key is not approved yet on https://emailrep.io/, so I can't implement the function.
# Query: Email
# Return: Info
def req_emailrep_email(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}"

    headers = {
        "Key": ihunt.apikeys.emailrep,
        "User-Agent": ihunt.user_agent,
    }

    try:
        resp = requests.get(url, headers=headers, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if is_empty(ihunt.data.email):
                    ihunt.data.email = d["email"]
                if is_empty(ihunt.data.domain_exists):
                    ihunt.data.domain_exists = d["details"]["domain_exists"]
                if is_empty(ihunt.data.domain_reputation):
                    ihunt.data.domain_reputation = d["details"]["domain_reputation"]
                if is_empty(ihunt.data.domain_new):
                    ihunt.data.domain_new = d["details"]["new_domain"]
                if is_empty(ihunt.data.free_provider):
                    ihunt.data.free_provider = d["details"]["free_provider"]
                if is_empty(ihunt.data.disposable):
                    ihunt.data.disposable = d["details"]["disposable"]
                if is_empty(ihunt.data.deliverable):
                    ihunt.data.deliverable = d["details"]["deliverable"]
                if is_empty(ihunt.data.spoofable):
                    ihunt.data.spoofable = d["details"]["spoofable"]
                if is_empty(ihunt.data.dmarc_enforced):
                    ihunt.data.dmarc_enforced = d["details"]["dmarc_enforced"]
                if is_empty(ihunt.data.accept_all):
                    ihunt.data.accept_all = d["details"]["accept_all"]
                if is_empty(ihunt.data.spam):
                    ihunt.data.spam = d["details"]["spam"]
                if is_empty(ihunt.data.suspicious):
                    ihunt.data.suspicious = d["suspicious"]
                if is_empty(ihunt.data.blacklisted):
                    ihunt.data.blacklisted = d["details"]["blacklisted"]
                if is_empty(ihunt.data.malicious_activity):
                    ihunt.data.malicious_activity = d["details"]["malicious_activity"]
                if is_empty(ihunt.data.malicious_activity_recent):
                    ihunt.data.malicious_activity_recent = d["details"]["malicious_activity_recent"]
                if is_empty(ihunt.data.credentials_leaked):
                    ihunt.data.credentials_leaked = d["details"]["credentials_leaked"]
                if is_empty(ihunt.data.credentials_leaked_recent):
                    ihunt.data.credentials_leaked_recent = d["details"]["credentials_leaked_recent"]
                if is_empty(ihunt.data.data_breach):
                    ihunt.data.data_breach = d["details"]["data_breach"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)