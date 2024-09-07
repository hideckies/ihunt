# Reference: https://docs.abuseipdb.com/#introduction

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

API_NAME = "AbuseIPDB"
BASE_URL = "https://api.abuseipdb.com/api/v2"


# Query: IP
# Return: Info
def req_abuseipdb_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + "/check"

    headers = {
        "Key": ihunt.apikeys.abuseipdb,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ihunt.query.value,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()["data"]
                if ihunt.data.ip is None:
                    ihunt.data.ip = d["ipAddress"]
                if ihunt.data.whitelisted is None:
                    ihunt.data.whitelisted = d["isWhitelisted"]
                if ihunt.data.country_code is None:
                    ihunt.data.country_code = d["countryCode"]
                if ihunt.data.country_name is None:
                    ihunt.data.country_name = d["countryName"]
                if ihunt.data.usage_type is None:
                    ihunt.data.usage_type = d["usageType"]
                if ihunt.data.isp is None:
                    ihunt.data.isp = d["isp"]
                if ihunt.data.domain is None:
                    ihunt.data.domain = d["domain"]
                if ihunt.data.hostnames is None:
                    ihunt.data.hostnames = d["hostnames"]
                if ihunt.data.is_tor is None:
                    ihunt.data.is_tor = d["isTor"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Fishined fetching {API_NAME}.", ihunt.verbose)
