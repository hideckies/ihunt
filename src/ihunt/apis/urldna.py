# Docs: https://urldna.io/api

import json
import requests
from threading import Lock
import time
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://api.urldna.io/scan"


# Query: URL
# Return: Info
def req_urldna_url(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching urlDNA...", ihunt.verbose)

    url = BASE_URL
    headers = {
        "Authorization": ihunt.apikeys.urldna,
        "Content-Type": "application/json",
    }
    data = {
        "submitted_url": ihunt.query.value,
    }

    try:
        resp = requests.post(url, headers=headers, data=json.dumps(data))
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
                    if ihunt.data.cert_issuer is None:
                        ihunt.data.cert_issuer = d["certificate"]["issuer"]
                    if ihunt.data.cert_subject is None:
                        ihunt.data.cert_subject = d["certificate"]["subject"]
                    if ihunt.data.cert_serial_number is None:
                        ihunt.data.cert_serial_number = d["certificate"]["serial_number"]
                    if ihunt.data.console_messages is None:
                        ihunt.data.console_messages = []
                        for msg in d["console_messages"]:
                            ihunt.data.console_messages.append(msg)
                    if ihunt.data.cookies is None:
                        ihunt.data.cookies = d["cookies"]
                    if ihunt.data.dom is None:
                        ihunt.data.dom = d["dom"]
                    if ihunt.data.favicon is None:
                        ihunt.data.favicon = d["favicon"]
                    if ihunt.data.ip is None:
                        ihunt.data.ip = d["ip_address"]["ip"]
                    if ihunt.data.asn is None:
                        ihunt.data.asn = d["ip_address"]["asn"]
                    if ihunt.data.isp is None:
                        ihunt.data.isp = d["ip_address"]["isp"]
                    if ihunt.data.organization is None:
                        ihunt.data.organization = d["ip_address"]["org"]
                    if ihunt.data.country_name is None:
                        ihunt.data.country_name = d["ip_address"]["country"]
                    if ihunt.data.country_code is None:
                        ihunt.data.country_code = d["ip_address"]["country_code"]
                    if ihunt.data.region is None:
                        ihunt.data.region = d["ip_address"]["region"]
                    if ihunt.data.city is None:
                        ihunt.data.city = d["ip_address"]["city"]
                    if ihunt.data.latitude is None:
                        ihunt.data.latitude = str(d["ip_address"]["latitude"])
                    if ihunt.data.longitude is None:
                        ihunt.data.longitude = str(d["ip_address"]["longitude"])
                    if ihunt.data.malicious is None:
                        ihunt.data.malicious = d["malicious"]
                    if ihunt.data.page is None:
                        ihunt.data.page = d["page"]
                    if ihunt.data.screenshot is None:
                        ihunt.data.screenshot = d["screenshot"]
                    if ihunt.data.technologies is None:
                        ihunt.data.technologies = d["technologies"]
                    break
    except Exception as e:
        echo(f"[x] urlDNA API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching urlDNA.", ihunt.verbose)