# Docs: https://hunter.io/api-documentation/v2

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

API_NAME = "Hunter"
BASE_URL = "https://api.hunter.io/v2"


# Query: Domain
# Return: Info
def req_hunter_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/domain-search"
    params = {
        "domain": ihunt.query.value,
        "api_key": ihunt.apikeys.hunter,
    }

    try:
        resp = requests.get(url, params=params)
        if resp.status_code == 200:
            with lock:
                d = resp.json()["data"]
                if is_empty(ihunt.data.domain):
                    ihunt.data.domain = d["domain"]
                if is_empty(ihunt.data.registrant_organization):
                    ihunt.data.registrant_organization = d["organization"]
                if is_empty(ihunt.data.registrant_desc):
                    ihunt.data.registrant_desc = d["description"]
                if is_empty(ihunt.data.registrant_industry):
                    ihunt.data.registrant_industry = d["industry"]
                if is_empty(ihunt.data.registrant_twitter):
                    ihunt.data.registrant_twitter = d["twitter"]
                if is_empty(ihunt.data.registrant_facebook):
                    ihunt.data.registrant_facebook = d["facebook"]
                if is_empty(ihunt.data.registrant_linkedin):
                    ihunt.data.registrant_linkedin = d["linkedin"]
                if is_empty(ihunt.data.registrant_instagram):
                    ihunt.data.registrant_instagram = d["instagram"]
                if is_empty(ihunt.data.registrant_youtube):
                    ihunt.data.registrant_youtube = d["youtube"]
                if is_empty(ihunt.data.registrant_country_code):
                    ihunt.data.registrant_country_code = d["country"]
                if is_empty(ihunt.data.registrant_state):
                    ihunt.data.registrant_state = d["state"]
                if is_empty(ihunt.data.registrant_city):
                    ihunt.data.registrant_city = d["city"]
                if is_empty(ihunt.data.registrant_street):
                    ihunt.data.registrant_street = d["street"]
                if is_empty(ihunt.data.registrant_postal_code):
                    ihunt.data.registrant_postal_code
                if len(d["emails"]) > 0:
                    for email in d["emails"]:
                        if is_empty(ihunt.data.emails):
                            ihunt.data.emails = [email["value"]]
                        else:
                            ihunt.data.emails.append(email["value"])
    except Exception as e:
        echo(f"[x] Hunter API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching Hunter.", ihunt.verbose)


# Query: Email
# Return: Verification
def req_hunter_email(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    url = BASE_URL + f"/email-verifier"
    params = {
        "email": ihunt.query.value,
        "api_key": ihunt.apikeys.hunter,
    }

    try:
        resp = requests.get(url, params=params, timeout=ihunt.timeout)

        if resp.status_code == 200:
            with lock:
                d = resp.json()["data"]
                if is_empty(ihunt.data.gibberish):
                    ihunt.data.gibberish = d["gibberish"]
                if is_empty(ihunt.data.disposable):
                    ihunt.data.disposable = d["disposable"]
                if is_empty(ihunt.data.webmail):
                    ihunt.data.webmail = d["webmail"]
                if is_empty(ihunt.data.mx_records):
                    ihunt.data.mx_records = d["mx_records"]
                if is_empty(ihunt.data.smtp_server):
                    ihunt.data.smtp_server = d["smtp_server"]
                if is_empty(ihunt.data.smtp_check):
                    ihunt.data.smtp_check = d["smtp_check"]
                if is_empty(ihunt.data.accept_all):
                    ihunt.data.accept_all = d["accept_all"]
                if is_empty(ihunt.data.block):
                    ihunt.data.block = d["block"]
    except Exception as e:
        echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}.", ihunt.verbose)