# Docs: https://ipapi.co/?q=78.48.50.249

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "IPAPI"
BASE_URL = "https://ipapi.co"


# Query: IP
# Return: Info
def req_ipapi_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/{ihunt.query.value}/json/"

    try:
        resp = requests.get(url, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if is_empty(ihunt.data.ip):
                    ihunt.data.ip = d["ip"]
                if is_empty(ihunt.data.net_range):
                    ihunt.data.net_range = d["network"]
                if is_empty(ihunt.data.region):
                    ihunt.data.region = d["region"]
                if is_empty(ihunt.data.country_code):
                    ihunt.data.country_code = d["country_code"]
                if is_empty(ihunt.data.country_name):
                    ihunt.data.country_name = d["country_name"]
                if is_empty(ihunt.data.postal_code):
                    ihunt.data.postal_code = d["postal"]
                if is_empty(ihunt.data.latitude):
                    ihunt.data.latitude = d["latitude"]
                if is_empty(ihunt.data.longitude):
                    ihunt.data.longitude = d["longitude"]
                if is_empty(ihunt.data.timezone):
                    ihunt.data.timezone = d["timezone"]
                if is_empty(ihunt.data.currency):
                    ihunt.data.currency = d["currency"]
                if is_empty(ihunt.data.currency_name):
                    ihunt.data.currency_name = d["currency_name"]
                if is_empty(ihunt.data.languages):
                    ihunt.data.languages = d["languages"].split(',')
                else:
                    for lang in d["languages"].split(','):
                        if lang not in ihunt.data.languages:
                            ihunt.data.languages.append(lang)
                if is_empty(ihunt.data.asn):
                    ihunt.data.asn = d["asn"]
                if is_empty(ihunt.data.organization):
                    ihunt.data.organization = d["org"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)
