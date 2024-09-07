# Docs: https://whois.whoisxmlapi.com/documentation/making-requests

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "WhoisXML"
BASE_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"


# Query: Domain
# Return: Info
def req_whoisxml_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL
    headers = {
        "Content-Type": "application/json",
    }
    data = {
        "domainName": ihunt.query.value,
        "outputFormat": "JSON",
        "apiKey": ihunt.apikeys.whoisxml,
    }

    try:
        resp = requests.post(url, headers=headers, json=data, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()["WhoisRecord"]
                if is_empty(ihunt.data.domain):
                    ihunt.data.domain = d["domainName"]
                if is_empty(ihunt.data.status):
                    ihunt.data.status = [d["status"]]
                # if is_empty(ihunt.data.availability):
                #     ihunt.data.availability = d["domainAvailability"]
                # if is_empty(ihunt.data.ips):
                #     ihunt.data.domain = d["ips"]
                if is_empty(ihunt.data.registrar_name):
                    ihunt.data.registrar_name = d["registryData"]["registrarName"]
                if is_empty(ihunt.data.registrar_iana_id):
                    ihunt.data.registrar_iana_id = d["registryData"]["registrarIANAID"]
                if is_empty(ihunt.data.registrant_organization):
                    ihunt.data.registrant_organization = d["registrant"]["organization"]
                if is_empty(ihunt.data.registrant_country):
                    ihunt.data.registrant_country = d["registrant"]["country"]
                if is_empty(ihunt.data.registrant_country_code):
                    ihunt.data.registrant_country_code = d["registrant"]["countryCode"]
                if is_empty(ihunt.data.registrant_state):
                    ihunt.data.registrant_state = d["registrant"]["state"]
                if is_empty(ihunt.data.registrant_city):
                    ihunt.data.registrant_city = d["registrant"]["city"]
                if is_empty(ihunt.data.admin_organization):
                    ihunt.data.admin_organization = d["administrativeContact"]["organization"]
                if is_empty(ihunt.data.admin_state):
                    ihunt.data.admin_state = d["administrativeContact"]["state"]
                if is_empty(ihunt.data.admin_country):
                    ihunt.data.admin_country = d["administrativeContact"]["country"]
                if is_empty(ihunt.data.admin_country_code):
                    ihunt.data.admin_country_code = d["administrativeContact"]["countryCode"]
                if is_empty(ihunt.data.tech_organization):
                    ihunt.data.tech_organization = d["technicalContact"]["organization"]
                if is_empty(ihunt.data.tech_country):
                    ihunt.data.tech_country = d["technicalContact"]["country"]
                if is_empty(ihunt.data.tech_country_code):
                    ihunt.data.tech_country_code = d["technicalContact"]["countryCode"]
                if is_empty(ihunt.data.tech_state):
                    ihunt.data.tech_state = d["technicalContact"]["state"]
                if is_empty(ihunt.data.name_servers):
                    ihunt.data.name_servers = d["nameServers"]["hostNames"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}...", ihunt.verbose)
