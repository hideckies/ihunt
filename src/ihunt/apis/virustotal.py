# Docs: https://docs.virustotal.com/reference/domain-info

import requests
from threading import Lock
import base64
import urllib.parse
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://www.virustotal.com/api/v3"


# Query: Domain
# Return: Info
def req_virustotal_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching VirusTotal...", ihunt.verbose)

    url = BASE_URL + f"/domains/{ihunt.query.value}"
    headers = {
        "accept": "application/json",
        "x-apikey": ihunt.apikeys.virustotal,
    }

    try:
        resp = requests.get(url, headers=headers)
        with lock:
            if resp.status_code == 200:
                d = resp.json()["data"]
                if ihunt.data.domain is None:
                    ihunt.data.domain = d["id"]
                if ihunt.data.virustotal_link is None:
                    ihunt.data.virustotal_link = d["links"]["self"]
                if ihunt.data.jarm is None:
                    ihunt.data.jarm = d["attributes"]["jarm"]
                if ihunt.data.virustotal_stats is None:
                    ihunt.data.virustotal_stats = d["attributes"]["last_analysis_stats"]
                if ihunt.data.virustotal_analysis is None:
                    ihunt.data.virustotal_analysis = d["attributes"]["last_analysis_results"]
                if ihunt.data.virustotal_votes is None:
                    ihunt.data.virustotal_votes = d["attributes"]["total_votes"]
                if ihunt.data.https_cert_signature_algorithm is None:
                    ihunt.data.https_cert_signature_algorithm = d["attributes"]["last_https_certificate"]["cert_signature"]["signature_algorithm"]
                if ihunt.data.https_cert_signature is None:
                    ihunt.data.https_cert_signature = d["attributes"]["last_https_certificate"]["cert_signature"]["signature"]
    except Exception as e:
        echo(f"[x] VirusTotal API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching VirusTotal.", ihunt.verbose)


# Query: IP
# Return: Info
def req_virustotal_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching VirusTotal...", ihunt.verbose)

    url = BASE_URL + f"/ip_addresses/{ihunt.query.value}"
    headers = {
        "accept": "application/json",
        "x-apikey": ihunt.apikeys.virustotal,
    }

    try:
        resp = requests.get(url, headers=headers)
        with lock:
            if resp.status_code == 200:
                d = resp.json()["data"]
                if ihunt.data.ip is None:
                    ihunt.data.ip = d["id"]
                if ihunt.data.virustotal_link is None:
                    ihunt.data.virustotal_link = d["links"]["self"]
                if ihunt.data.asn is None:
                    ihunt.data.asn = d["attributes"]["asn"]
                if ihunt.data.virustotal_analysis is None:
                    ihunt.data.virustotal_analysis = d["attributes"]["last_analysis_results"]
                if ihunt.data.jarm is None:
                    ihunt.data.jarm = d["attributes"]["jarm"]
                if ihunt.data.country_code is None:
                    ihunt.data.country_code = d["attributes"]["country"]
                if ihunt.data.net_range is None:
                    ihunt.data.net_range = d["attributes"]["network"]
                if ihunt.data.virustotal_stats is None:
                    ihunt.data.virustotal_stats = d["attributes"]["last_analysis_stats"]
                if ihunt.data.virustotal_votes is None:
                    ihunt.data.virustotal_votes = d["attributes"]["total_votes"]
                if ihunt.data.https_cert_signature_algorithm is None:
                    ihunt.data.https_cert_signature_algorithm = d["attributes"]["last_https_certificate"]["cert_signature"]["signature_algorithm"]
                if ihunt.data.https_cert_signature is None:
                    ihunt.data.https_cert_signature = d["attributes"]["last_https_certificate"]["cert_signature"]["signature"]
    except Exception as e:
        echo(f"[x] VirusTotal API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching VirusTotal.", ihunt.verbose)


# Query: URL
# Return: Info
def req_virustotal_url(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching VirusTotal...", ihunt.verbose)

    target_url = urllib.parse.quote(base64.b64encode(ihunt.query.value.encode('utf-8')).decode('utf-8'))

    url = BASE_URL + f"/urls/{target_url}"
    headers = {
        "accept": "application/json",
        "x-apikey": ihunt.apikeys.virustotal,
    }

    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            with lock:
                d = resp.json()["data"]
                if ihunt.data.virustotal_link is None:
                    ihunt.data.virustotal_link = d["links"]["self"]
                if ihunt.data.url is None:
                    ihunt.data.url = d["attributes"]["url"]
                if ihunt.data.virustotal_votes is None:
                    ihunt.data.virustotal_votes = d["attributes"]["total_votes"]
                if ihunt.data.virustotal_stats is None:
                    ihunt.data.virustotal_stats = d["attributes"]["last_analysis_stats"]
                if ihunt.data.virustotal_analysis is None:
                    ihunt.data.virustotal_analysis = d["attributes"]["last_analysis_results"]
                if ihunt.data.virustotal_threat_names is None:
                    ihunt.data.virustotal_threat_names = d["attributes"]["threat_names"]
    except Exception as e:
        echo(f"[x] VirusTotal API error {e}", ihunt.verbose)

    echo("[*] finished fetching VirusTotal.", ihunt.verbose)