# Docs: https://urldna.io/api

import json
import requests
from threading import Lock
import time
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "urlDNA"
BASE_URL = "https://api.urldna.io/scan"


# Query: URL
# Return: Info
def req_urldna_url(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL
    headers = {
        "Authorization": ihunt.apikeys.urldna,
        "Content-Type": "application/json",
    }
    data = {
        "submitted_url": ihunt.query.value,
    }

    try:
        resp = requests.post(url, headers=headers, data=json.dumps(data), timeout=ihunt.timeout)
        if resp.status_code != 200:
            return
        with lock:
            d = resp.json()
            scan_id = d["id"]
            url = BASE_URL + f"/{scan_id}"

            # Get scan result (wait for the scan status is "DONE")
            while True:
                echo("[*] Waiting for the scan result...", ihunt.verbose)
                time.sleep(5)

                resp = requests.get(url, headers=headers)
                if resp.status_code != 200:
                    return
            
                d = resp.json()
                scan_status = d["scan"]["status"]

                if scan_status == "RUNNING" or scan_status == "PENDING":
                    continue
                elif scan_status == "ERROR":
                    echo(f"[x] urlDNA API error: The scan failed.", ihunt.verbose)
                    return
                elif scan_status == "DONE":
                    if is_empty(ihunt.data.cert_issuer):
                        ihunt.data.cert_issuer = d["certificate"]["issuer"]
                    if is_empty(ihunt.data.cert_subject):
                        ihunt.data.cert_subject = d["certificate"]["subject"]
                    if is_empty(ihunt.data.cert_serial_number):
                        ihunt.data.cert_serial_number = d["certificate"]["serial_number"]
                    if is_empty(ihunt.data.console_messages):
                        ihunt.data.console_messages = []
                        for msg in d["console_messages"]:
                            ihunt.data.console_messages.append(msg)
                    if is_empty(ihunt.data.cookies):
                        ihunt.data.cookies = d["cookies"]
                    if is_empty(ihunt.data.dom):
                        ihunt.data.dom = d["dom"]
                    if is_empty(ihunt.data.favicon):
                        ihunt.data.favicon = d["favicon"]
                    if is_empty(ihunt.data.ip):
                        ihunt.data.ip = d["ip_address"]["ip"]
                    if is_empty(ihunt.data.asn):
                        ihunt.data.asn = d["ip_address"]["asn"]
                    if is_empty(ihunt.data.isp):
                        ihunt.data.isp = d["ip_address"]["isp"]
                    if is_empty(ihunt.data.organization):
                        ihunt.data.organization = d["ip_address"]["org"]
                    if is_empty(ihunt.data.country_name):
                        ihunt.data.country_name = d["ip_address"]["country"]
                    if is_empty(ihunt.data.country_code):
                        ihunt.data.country_code = d["ip_address"]["country_code"]
                    if is_empty(ihunt.data.region):
                        ihunt.data.region = d["ip_address"]["region"]
                    if is_empty(ihunt.data.city):
                        ihunt.data.city = d["ip_address"]["city"]
                    if is_empty(ihunt.data.latitude):
                        ihunt.data.latitude = str(d["ip_address"]["latitude"])
                    if is_empty(ihunt.data.longitude):
                        ihunt.data.longitude = str(d["ip_address"]["longitude"])
                    if is_empty(ihunt.data.malicious):
                        ihunt.data.malicious = d["malicious"]
                    if is_empty(ihunt.data.page):
                        ihunt.data.page = d["page"]
                    if is_empty(ihunt.data.screenshot):
                        ihunt.data.screenshot = d["screenshot"]
                    if is_empty(ihunt.data.technologies):
                        ihunt.data.technologies = d["technologies"]
                    break
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)