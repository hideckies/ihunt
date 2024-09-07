# Docs: https://otx.alienvault.com/api

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty, is_ip_address

API_NAME = "AlienVaule"
BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain"


# Query: Domain
# Return: Subdomains
def req_alienvalut_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}/passive_dns"

    try:
        resp = requests.get(url, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                data = resp.json()["passive_dns"]
                for d in data:
                    if is_ip_address(d["address"]):
                        if is_empty(ihunt.data.ips):
                            ihunt.data.ips = [d["address"]]
                        else:
                            if d["address"] not in ihunt.data.ips:
                                ihunt.data.ips.append(d["address"])
                    if is_ip_address(d["hostname"]) is False:
                        if is_empty(ihunt.data.subdomains):
                            ihunt.data.subdomains = [d["hostname"]]
                        else:
                            if d["hostname"] not in ihunt.data.subdomains:
                                ihunt.data.subdomains.append(d["hostname"])
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)
        