# Docs: https://docs.virustotal.com/reference/domain-info

import requests
from threading import Lock
import base64
import urllib.parse
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "VirusTotal"
BASE_URL = "https://www.virustotal.com/api/v3"


# Query: Domain
# Return: Info
def req_virustotal_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/domains/{ihunt.query.value}"
    headers = {
        "accept": "application/json",
        "x-apikey": ihunt.apikeys.virustotal,
    }

    try:
        resp = requests.get(url, headers=headers, timeout=ihunt.timeout)
        with lock:
            if resp.status_code == 200:
                d = resp.json()["data"]
                if is_empty(ihunt.data.domain):
                    ihunt.data.domain = d["id"]
                if is_empty(ihunt.data.virustotal_link):
                    ihunt.data.virustotal_link = d["links"]["self"]
                if is_empty(ihunt.data.jarm):
                    ihunt.data.jarm = d["attributes"]["jarm"]
                if is_empty(ihunt.data.virustotal_stats):
                    ihunt.data.virustotal_stats = d["attributes"]["last_analysis_stats"]
                if is_empty(ihunt.data.virustotal_analysis):
                    ihunt.data.virustotal_analysis = d["attributes"]["last_analysis_results"]
                if is_empty(ihunt.data.virustotal_votes):
                    ihunt.data.virustotal_votes = d["attributes"]["total_votes"]
                if is_empty(ihunt.data.https_cert_signature_algorithm):
                    ihunt.data.https_cert_signature_algorithm = d["attributes"]["last_https_certificate"]["cert_signature"]["signature_algorithm"]
                if is_empty(ihunt.data.https_cert_signature):
                    ihunt.data.https_cert_signature = d["attributes"]["last_https_certificate"]["cert_signature"]["signature"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)


# Query: Hash
# Return: Info
def req_virustotal_hash(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/files/{ihunt.query.value}"
    headers = {
        "accept": "application/json",
        "x-apikey": ihunt.apikeys.virustotal,
    }

    try:
        resp = requests.get(url, headers=headers, timeout=ihunt.timeout)
        with lock:
            if resp.status_code == 200:
                d = resp.json()["data"]
                if is_empty(ihunt.data.hash):
                    ihunt.data.hash = d["id"]
                if is_empty(ihunt.data.virustotal_link):
                    ihunt.data.virustotal_link = d["links"]["self"]
                if is_empty(ihunt.data.filetype):
                    ihunt.data.filetype = d["attributes"]["detectiteasy"]["filetype"]
                if is_empty(ihunt.data.filenames):
                    ihunt.data.filenames = d["attributes"]["names"]
                else:
                    # Update filenames array
                    for name in d["attributes"]["names"]:
                        if name not in ihunt.data.filenames:
                            ihunt.data.filenames.append(name)
                if is_empty(ihunt.data.tlsh):
                    ihunt.data.tlsh = d["attributes"]["tlsh"]
                if is_empty(ihunt.data.sha1):
                    ihunt.data.sha1 = d["attributes"]["sha1"]
                if is_empty(ihunt.data.sha256):
                    ihunt.data.sha256 = d["attributes"]["sha256"]
                if is_empty(ihunt.data.md5):
                    ihunt.data.md5 = d["attributes"]["md5"]
                if is_empty(ihunt.data.ssdeep):
                    ihunt.data.ssdeep = d["attributes"]["ssdeep"]
                if is_empty(ihunt.data.vhash):
                    ihunt.data.vhash = d["attributes"]["vhash"]
                if is_empty(ihunt.data.telfhash):
                    ihunt.data.telfhash = d["attributes"]["telfhash"]
                if is_empty(ihunt.data.virustotal_stats):
                    ihunt.data.virustotal_stats = d["attributes"]["last_analysis_stats"]
                if is_empty(ihunt.data.virustotal_analysis):
                    ihunt.data.virustotal_analysis = d["attributes"]["last_analysis_results"]
                if is_empty(ihunt.data.virustotal_votes):
                    ihunt.data.virustotal_votes = d["attributes"]["total_votes"]
                if is_empty(ihunt.data.elf_info):
                    ihunt.data.elf_info = d["attributes"]["elf_info"]
                if is_empty(ihunt.data.pe_info):
                    ihunt.data.pe_info = d["attributes"]["pe_info"]
                if is_empty(ihunt.data.filesize):
                    ihunt.data.filesize = d["attributes"]["size"]
                if is_empty(ihunt.data.magic):
                    ihunt.data.magic = d["attributes"]["magic"]

                if is_empty(ihunt.data.jarm):
                    ihunt.data.jarm = d["attributes"]["jarm"]
                if is_empty(ihunt.data.https_cert_signature_algorithm):
                    ihunt.data.https_cert_signature_algorithm = d["attributes"]["last_https_certificate"]["cert_signature"]["signature_algorithm"]
                if is_empty(ihunt.data.https_cert_signature):
                    ihunt.data.https_cert_signature = d["attributes"]["last_https_certificate"]["cert_signature"]["signature"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)


# Query: IP
# Return: Info
def req_virustotal_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/ip_addresses/{ihunt.query.value}"
    headers = {
        "accept": "application/json",
        "x-apikey": ihunt.apikeys.virustotal,
    }

    try:
        resp = requests.get(url, headers=headers, timeout=ihunt.timeout)
        with lock:
            if resp.status_code == 200:
                d = resp.json()["data"]
                if ihunt.data.ip is None:
                    ihunt.data.ip = d["id"]
                if is_empty(ihunt.data.virustotal_link):
                    ihunt.data.virustotal_link = d["links"]["self"]
                if is_empty(ihunt.data.asn):
                    ihunt.data.asn = d["attributes"]["asn"]
                if is_empty(ihunt.data.virustotal_analysis):
                    ihunt.data.virustotal_analysis = d["attributes"]["last_analysis_results"]
                if is_empty(ihunt.data.jarm):
                    ihunt.data.jarm = d["attributes"]["jarm"]
                if is_empty(ihunt.data.country_code):
                    ihunt.data.country_code = d["attributes"]["country"]
                if is_empty(ihunt.data.net_range):
                    ihunt.data.net_range = d["attributes"]["network"]
                if is_empty(ihunt.data.virustotal_stats):
                    ihunt.data.virustotal_stats = d["attributes"]["last_analysis_stats"]
                if is_empty(ihunt.data.virustotal_votes):
                    ihunt.data.virustotal_votes = d["attributes"]["total_votes"]
                if is_empty(ihunt.data.https_cert_signature_algorithm):
                    ihunt.data.https_cert_signature_algorithm = d["attributes"]["last_https_certificate"]["cert_signature"]["signature_algorithm"]
                if is_empty(ihunt.data.https_cert_signature):
                    ihunt.data.https_cert_signature = d["attributes"]["last_https_certificate"]["cert_signature"]["signature"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)


# Query: URL
# Return: Info
def req_virustotal_url(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    target_url = urllib.parse.quote(base64.b64encode(ihunt.query.value.encode('utf-8')).decode('utf-8'))

    url = BASE_URL + f"/urls/{target_url}"
    headers = {
        "accept": "application/json",
        "x-apikey": ihunt.apikeys.virustotal,
    }

    try:
        resp = requests.get(url, headers=headers, timeout=ihunt.timeout)
        if resp.status_code == 200:
            with lock:
                d = resp.json()["data"]
                if is_empty(ihunt.data.virustotal_link):
                    ihunt.data.virustotal_link = d["links"]["self"]
                if is_empty(ihunt.data.url):
                    ihunt.data.url = d["attributes"]["url"]
                if is_empty(ihunt.data.virustotal_votes):
                    ihunt.data.virustotal_votes = d["attributes"]["total_votes"]
                if is_empty(ihunt.data.virustotal_stats):
                    ihunt.data.virustotal_stats = d["attributes"]["last_analysis_stats"]
                if is_empty(ihunt.data.virustotal_analysis):
                    ihunt.data.virustotal_analysis = d["attributes"]["last_analysis_results"]
                if is_empty(ihunt.data.virustotal_threat_names):
                    ihunt.data.virustotal_threat_names = d["attributes"]["threat_names"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error {e}", ihunt.verbose)

    echo(f"[*] finished fetching {API_NAME}.", ihunt.verbose)