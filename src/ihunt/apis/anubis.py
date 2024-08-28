# Docs: https://github.com/jonluca/anubis

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://jonlu.ca/anubis/subdomains"


# Query: Domain
# Return: Subdomains
def req_anubis_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching Anubis...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}"

    try:
        resp = requests.get(url, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                subdomains = resp.json()
                for subdomain in subdomains:
                    if ihunt.data.subdomains is None:
                        ihunt.data.subdomains = [subdomain]
                    else:
                        if subdomain not in ihunt.data.subdomains:
                            ihunt.data.subdomains.append(subdomain)
    except Exception as e:
        echo(f"[x] Anubis API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching Anubis...", ihunt.verbose)
