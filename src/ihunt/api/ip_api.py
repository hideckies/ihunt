# Docs: https://ip-api.com/docs/api:json

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "ip-api"
BASE_URL = "http://ip-api.com/json"


# Query: IP
# Return: Info
def req_ip_api_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = f"{BASE_URL}/{ihunt.query.value}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,currency,isp,org,as,reverse,mobile,proxy,hosting,query"

    try:
        resp = requests.get(url, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()
                if d["status"] != "success":
                    return
                if is_empty(ihunt.data.ip):
                    ihunt.data.ip = d["query"]
                if is_empty(ihunt.data.country_name):
                    ihunt.data.country_name = d["country"]
                if is_empty(ihunt.data.country_code):
                    ihunt.data.country_code = d["countryCode"]
                if is_empty(ihunt.data.region):
                    ihunt.data.region = d["regionName"]
                if is_empty(ihunt.data.city):
                    ihunt.data.city = d["city"]
                if is_empty(ihunt.data.latitude):
                    ihunt.data.latitude = d["latitude"]
                if is_empty(ihunt.data.longitude):
                    ihunt.data.longitude = d["longitude"]
                if is_empty(ihunt.data.timezone):
                    ihunt.data.timezone = d["timezone"]
                if is_empty(ihunt.data.currency):
                    ihunt.data.currency = d["currency"]
                if is_empty(ihunt.data.isp):
                    ihunt.data.isp = d["isp"]
                if is_empty(ihunt.data.domain):
                    ihunt.data.domain = d["reverse"]
                if is_empty(ihunt.data.organization):
                    ihunt.data.organization = d["organization"]
                if is_empty(ihunt.data.is_proxy):
                    ihunt.data.is_proxy = d["proxy"]
                if is_empty(ihunt.data.is_mobile):
                    ihunt.data.is_mobile = d["mobile"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)
