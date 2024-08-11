import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://api.hackertarget.com/hostsearch"


# Query: Domain
# Return: Subdomains, IPs
def req_hackertarget_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching HackerTarget...", ihunt.verbose)

    url = BASE_URL + f"/?q={ihunt.query.value}"

    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            with lock:
                lines = resp.content.decode().split('\n')
                for line in lines:
                    spl = line.split(',')
                    # Subdomain
                    if ihunt.data.subdomains is None:
                        ihunt.data.subdomains = [spl[0]]
                    else:
                        if spl[0] not in ihunt.data.subdomains:
                            ihunt.data.subdomains.append(spl[0])
                    # IP
                    if len(spl) == 2:
                        if ihunt.data.ips is None:
                            ihunt.data.ips = [spl[1]]
                        else:
                            if spl[1] not in ihunt.data.ips:
                                ihunt.data.ips.append(spl[1])
    except Exception as e:
        echo(f"[x] HackerTarget API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching HackerTarget.", ihunt.verbose)
