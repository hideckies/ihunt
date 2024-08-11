# Docs: https://hunter.io/api-documentation/v2

import requests
from threading import Lock
from ..models import Ihunt
from ..stdout import echo

BASE_URL = "https://api.hunter.io/v2"


# Query: Domain
# Return: Info
def req_hunter_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching Hunter...", ihunt.verbose)

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
                if ihunt.data.domain is None:
                    ihunt.data.domain = d["domain"]
                if ihunt.data.registrant_organization is None:
                    ihunt.data.registrant_organization = d["organization"]
                if ihunt.data.registrant_desc is None:
                    ihunt.data.registrant_desc = d["description"]
                if ihunt.data.registrant_industry is None:
                    ihunt.data.registrant_industry = d["industry"]
                if ihunt.data.registrant_twitter is None:
                    ihunt.data.registrant_twitter = d["twitter"]
                if ihunt.data.registrant_facebook is None:
                    ihunt.data.registrant_facebook = d["facebook"]
                if ihunt.data.registrant_linkedin is None:
                    ihunt.data.registrant_linkedin = d["linkedin"]
                if ihunt.data.registrant_instagram is None:
                    ihunt.data.registrant_instagram = d["instagram"]
                if ihunt.data.registrant_youtube is None:
                    ihunt.data.registrant_youtube = d["youtube"]
                if ihunt.data.registrant_country_code is None:
                    ihunt.data.registrant_country_code = d["country"]
                if ihunt.data.registrant_state is None:
                    ihunt.data.registrant_state = d["state"]
                if ihunt.data.registrant_city is None:
                    ihunt.data.registrant_city = d["city"]
                if ihunt.data.registrant_street is None:
                    ihunt.data.registrant_street = d["street"]
                if ihunt.data.registrant_postal_code is None:
                    ihunt.data.registrant_postal_code
                if len(d["emails"]) > 0:
                    for email in d["emails"]:
                        if ihunt.data.emails is None:
                            ihunt.data.emails = [email["value"]]
                        else:
                            ihunt.data.emails.append(email["value"])
    except Exception as e:
        echo(f"[x] Hunter API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching Hunter.", ihunt.verbose)


# Query: Email
# Return: Verification
def req_hunter_email(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Fetching Hunter...", ihunt.verbose)

    url = BASE_URL + f"/email-verifier"
    params = {
        "email": ihunt.query.value,
        "api_key": ihunt.apikeys.hunter,
    }

    try:
        resp = requests.get(url, params=params)

        if resp.status_code == 200:
            with lock:
                d = resp.json()["data"]
                if ihunt.data.gibberish is None:
                    ihunt.data.gibberish = d["gibberish"]
                if ihunt.data.disposable is None:
                    ihunt.data.disposable = d["disposable"]
                if ihunt.data.webmail is None:
                    ihunt.data.webmail = d["webmail"]
                if ihunt.data.mx_records is None:
                    ihunt.data.mx_records = d["mx_records"]
                if ihunt.data.smtp_server is None:
                    ihunt.data.smtp_server = d["smtp_server"]
                if ihunt.data.smtp_check is None:
                    ihunt.data.smtp_check = d["smtp_check"]
                if ihunt.data.accept_all is None:
                    ihunt.data.accept_all = d["accept_all"]
                if ihunt.data.block is None:
                    ihunt.data.block = d["block"]
    except Exception as e:
        echo("[x] Hunter API error: {e}", ihunt.verbose)

    echo("[*] Finished fetching Hunter.", ihunt.verbose)