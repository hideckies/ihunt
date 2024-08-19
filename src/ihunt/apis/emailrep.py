# Docs: https://docs.sublime.security/reference/emailrep-introduction

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://emailrep.io"

# TODO: The API key is not approved yet on https://emailrep.io/, so I can't implement the function.
# Query: Email
# Return: Info
def req_emailrep_email(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching Emailrep...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}"

    headers = {
        "Key": ihunt.apikeys.emailrep,
        "User-Agent": ihunt.user_agent,
    }

    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if ihunt.data.email is None:
                    ihunt.data.email = d["email"]
                if ihunt.data.domain_exists is None:
                    ihunt.data.domain_exists = d["details"]["domain_exists"]
                if ihunt.data.domain_reputation is None:
                    ihunt.data.domain_reputation = d["details"]["domain_reputation"]
                if ihunt.data.domain_new is None:
                    ihunt.data.domain_new = d["details"]["new_domain"]
                if ihunt.data.free_provider is None:
                    ihunt.data.free_provider = d["details"]["free_provider"]
                if ihunt.data.disposable is None:
                    ihunt.data.disposable = d["details"]["disposable"]
                if ihunt.data.deliverable is None:
                    ihunt.data.deliverable = d["details"]["deliverable"]
                if ihunt.data.spoofable is None:
                    ihunt.data.spoofable = d["details"]["spoofable"]
                if ihunt.data.dmarc_enforced is None:
                    ihunt.data.dmarc_enforced = d["details"]["dmarc_enforced"]
                if ihunt.data.accept_all is None:
                    ihunt.data.accept_all = d["details"]["accept_all"]
                if ihunt.data.spam is None:
                    ihunt.data.spam = d["details"]["spam"]
                if ihunt.data.suspicious is None:
                    ihunt.data.suspicious = d["suspicious"]
                if ihunt.data.blacklisted is None:
                    ihunt.data.blacklisted = d["details"]["blacklisted"]
                if ihunt.data.malicious_activity is None:
                    ihunt.data.malicious_activity = d["details"]["malicious_activity"]
                if ihunt.data.malicious_activity_recent is None:
                    ihunt.data.malicious_activity_recent = d["details"]["malicious_activity_recent"]
                if ihunt.data.credentials_leaked is None:
                    ihunt.data.credentials_leaked = d["details"]["credentials_leaked"]
                if ihunt.data.credentials_leaked_recent is None:
                    ihunt.data.credentials_leaked_recent = d["details"]["credentials_leaked_recent"]
                if ihunt.data.data_breach is None:
                    ihunt.data.data_breach = d["details"]["data_breach"]
    except Exception as e:
        echo(f"[x] Emailrep API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching Emailrep...", ihunt.verbose)