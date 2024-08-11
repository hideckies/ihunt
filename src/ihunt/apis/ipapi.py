# Docs: https://ipapi.co/?q=78.48.50.249

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://ipapi.co"


# Query: IP
# Return: Info
def req_ipapi_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching IPAPI...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}/json/"

    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if ihunt.data.ip is None:
                    ihunt.data.ip = d["ip"]
                if ihunt.data.net_range is None:
                    ihunt.data.net_range = d["network"]
                if ihunt.data.region is None:
                    ihunt.data.region = d["region"]
                if ihunt.data.country_code is None:
                    ihunt.data.country_code = d["country_code"]
                if ihunt.data.country_name is None:
                    ihunt.data.country_name = d["country_name"]
                if ihunt.data.postal_code is None:
                    ihunt.data.postal_code = d["postal"]
                if ihunt.data.latitude is None:
                    ihunt.data.latitude = d["latitude"]
                if ihunt.data.longitude is None:
                    ihunt.data.longitude = d["longitude"]
                if ihunt.data.timezone is None:
                    ihunt.data.timezone = d["timezone"]
                if ihunt.data.currency is None:
                    ihunt.data.currency = d["currency"]
                if ihunt.data.currency_name is None:
                    ihunt.data.currency_name = d["currency_name"]
                if ihunt.data.languages is None:
                    ihunt.data.languages = d["languages"].split(',')
                else:
                    for lang in d["languages"].split(','):
                        if lang not in ihunt.data.languages:
                            ihunt.data.languages.append(lang)
                if ihunt.data.asn is None:
                    ihunt.data.asn = d["asn"]
                if ihunt.data.organization is None:
                    ihunt.data.organization = d["org"]
    except Exception as e:
        echo(f"[x] IPAPI API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching IPAPI.", ihunt.verbose)
