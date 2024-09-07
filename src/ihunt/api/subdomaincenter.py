# Docs: https://github.com/ARPSyndicate/docs?tab=readme-ov-file#subdomain-center

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "SubdomainCenter"
BASE_URL = "https://api.subdomain.center/?domain=google.com"


# Query: Domain
# Return: Subdomains
def req_subdomaincenter_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/?domain={ihunt}"

    try:
        resp = requests.get(url, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                subdomains = resp.json()
                for subdomain in subdomains:
                    if is_empty(ihunt.data.subdomains):
                        ihunt.data.subdomains = [subdomain]
                    else:
                        if subdomain not in ihunt.data.subdomains:
                            ihunt.data.subdomains.append(subdomain)
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}...", ihunt.verbose)
