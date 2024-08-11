# Docs: https://whois.whoisxmlapi.com/documentation/making-requests

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"


# Query: Domain
# Return: Info
def req_whoisxml_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching WhoisXML...", ihunt.verbose)

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
        resp = requests.post(url, headers=headers, json=data)
        if resp.status_code == 200:
            with lock:
                d = resp.json()["WhoisRecord"]
                if ihunt.data.domain is None:
                    ihunt.data.domain = d["domainName"]
                if ihunt.data.status is None:
                    ihunt.data.status = [d["status"]]
                # if ihunt.data.availability is None:
                #     ihunt.data.availability = d["domainAvailability"]
                # if ihunt.data.ips is None:
                #     ihunt.data.domain = d["ips"]
                if ihunt.data.registrar_name is None:
                    ihunt.data.registrar_name = d["registryData"]["registrarName"]
                if ihunt.data.registrar_iana_id is None:
                    ihunt.data.registrar_iana_id = d["registryData"]["registrarIANAID"]
                if ihunt.data.registrant_organization is None:
                    ihunt.data.registrant_organization = d["registrant"]["organization"]
                if ihunt.data.registrant_country is None:
                    ihunt.data.registrant_country = d["registrant"]["country"]
                if ihunt.data.registrant_country_code is None:
                    ihunt.data.registrant_country_code = d["registrant"]["countryCode"]
                if ihunt.data.registrant_state is None:
                    ihunt.data.registrant_state = d["registrant"]["state"]
                if ihunt.data.registrant_city is None:
                    ihunt.data.registrant_city = d["registrant"]["city"]
                if ihunt.data.admin_organization is None:
                    ihunt.data.admin_organization = d["administrativeContact"]["organization"]
                if ihunt.data.admin_state is None:
                    ihunt.data.admin_state = d["administrativeContact"]["state"]
                if ihunt.data.admin_country is None:
                    ihunt.data.admin_country = d["administrativeContact"]["country"]
                if ihunt.data.admin_country_code is None:
                    ihunt.data.admin_country_code = d["administrativeContact"]["countryCode"]
                if ihunt.data.tech_organization is None:
                    ihunt.data.tech_organization = d["technicalContact"]["organization"]
                if ihunt.data.tech_country is None:
                    ihunt.data.tech_country = d["technicalContact"]["country"]
                if ihunt.data.tech_country_code is None:
                    ihunt.data.tech_country_code = d["technicalContact"]["countryCode"]
                if ihunt.data.tech_state is None:
                    ihunt.data.tech_state = d["technicalContact"]["state"]
                if ihunt.data.name_servers is None:
                    ihunt.data.name_servers = d["nameServers"]["hostNames"]
    except Exception as e:
        echo(f"[x] WhoisXML API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching WhoisXML...", ihunt.verbose)
