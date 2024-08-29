import threading
from .apis.abuseipdb import req_abuseipdb_ip
from .apis.alienvault import req_alienvalut_domain
from .apis.anubis import req_anubis_domain
from .apis.duckduckgo import req_duckduckgo
from .apis.emailrep import req_emailrep_email
from .apis.eva import req_eva_email
from .apis.groq import req_groq
from .apis.hackertarget import req_hackertarget_domain
from .apis.hunter import req_hunter_domain, req_hunter_email
from .apis.ipapi import req_ipapi_ip
from .apis.pulsedive import req_pulsedive_domain, req_pulsedive_ip
from .apis.robtex import req_robtex_ip
from .apis.subdomaincenter import req_subdomaincenter_domain
from .apis.urldna import req_urldna_url
from .apis.virustotal import req_virustotal_domain, req_virustotal_hash, req_virustotal_ip, req_virustotal_url
from .apis.whoisxml import req_whoisxml_domain
from .cmds.dig import exec_dig_domain
from .cmds.whois import exec_whois_domain, exec_whois_ip
from .querytype import QueryType
from .models import (
    DataDomain,
    DataEmail,
    DataHash,
    DataIp,
    DataOrg,
    DataPerson,
    DataPhone,
    DataUrl,
    Ihunt,
)
from .stdout import echo

lock = threading.Lock()


def gather_domain(ihunt: Ihunt) -> None:
    threads = []

    thread = threading.Thread(target=exec_dig_domain, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    thread = threading.Thread(target=exec_whois_domain, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    thread = threading.Thread(target=req_alienvalut_domain, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    thread = threading.Thread(target=req_anubis_domain, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    thread = threading.Thread(target=req_hackertarget_domain, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.hunter:
        thread = threading.Thread(target=req_hunter_domain, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Hunter API key is not set.", ihunt.verbose)

    if ihunt.apikeys.pulsedive:
        thread = threading.Thread(target=req_pulsedive_domain, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Pulsedive API key is not set.", ihunt.verbose)

    thread = threading.Thread(target=req_subdomaincenter_domain, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.virustotal:
        thread = threading.Thread(target=req_virustotal_domain, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] VirusTotal API key is not set.", ihunt.verbose)

    if ihunt.apikeys.whoisxml:
        thread = threading.Thread(target=req_whoisxml_domain, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] WhoisXML API key is not set.", ihunt.verbose)

    # ------------------------------------------------------------------------------
    # Execute AI-related APIs lastly from the perspective of accuracy
    # ------------------------------------------------------------------------------

    thread = threading.Thread(target=req_duckduckgo, args=(ihunt, lock, DataDomain))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.groq:
        thread = threading.Thread(target=req_groq, args=(ihunt, lock, DataDomain))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Groq API key is not set.", ihunt.verbose)

    for thread in threads:
        thread.join()


def gather_email(ihunt: Ihunt) -> None:
    threads = []

    thread = threading.Thread(target=req_emailrep_email, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    thread = threading.Thread(target=req_eva_email, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.hunter:
        thread = threading.Thread(target=req_hunter_email, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Hunter API key is not set.", ihunt.verbose)

    # ------------------------------------------------------------------------------
    # Execute AI-related APIs lastly from the perspective of accuracy
    # ------------------------------------------------------------------------------

    thread = threading.Thread(target=req_duckduckgo, args=(ihunt, lock, DataEmail))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.groq:
        thread = threading.Thread(target=req_groq, args=(ihunt, lock, DataEmail))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Groq API key is not set.", ihunt.verbose)

    for thread in threads:
        thread.join()


def gather_hash(ihunt: Ihunt) -> None:
    threads = []

    if ihunt.apikeys.virustotal:
        thread = threading.Thread(target=req_virustotal_hash, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] VirusTotal API key is not set.", ihunt.verbose)

    # ------------------------------------------------------------------------------
    # Execute AI-related APIs lastly from the perspective of accuracy
    # ------------------------------------------------------------------------------

    thread = threading.Thread(target=req_duckduckgo, args=(ihunt, lock, DataHash))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.groq:
        thread = threading.Thread(target=req_groq, args=(ihunt, lock, DataHash))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Groq API key is not set.", ihunt.verbose)

    for thread in threads:
        thread.join()


def gather_ip(ihunt: Ihunt) -> None:
    threads = []

    thread = threading.Thread(target=exec_whois_ip, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.abuseipdb:
        thread = threading.Thread(target=req_abuseipdb_ip, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] AbuseIPDB API key is not set.", ihunt.verbose)

    thread = threading.Thread(target=req_ipapi_ip, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.pulsedive:
        thread = threading.Thread(target=req_ipapi_ip, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Pulsedive API key is not set.", ihunt.verbose)

    thread = threading.Thread(target=req_robtex_ip, args=(ihunt, lock))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.virustotal:
        thread = threading.Thread(target=req_virustotal_ip, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] VirusTotal API key is not set.", ihunt.verbose)

    # ------------------------------------------------------------------------------
    # Execute AI-related APIs lastly from the perspective of accuracy
    # ------------------------------------------------------------------------------

    thread = threading.Thread(target=req_duckduckgo, args=(ihunt, lock, DataIp))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.groq:
        thread = threading.Thread(target=req_groq, args=(ihunt, lock, DataIp))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Groq API key is not set.", ihunt.verbose)

    for thread in threads:
        thread.join()


def gather_org(ihunt: Ihunt) -> None:
    threads = []

    # ------------------------------------------------------------------------------
    # Execute AI-related APIs lastly from the perspective of accuracy
    # ------------------------------------------------------------------------------

    thread = threading.Thread(target=req_duckduckgo, args=(ihunt, lock, DataOrg))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.groq:
        thread = threading.Thread(target=req_groq, args=(ihunt, lock, DataOrg))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Groq API key is not set.", ihunt.verbose)

    for thread in threads:
        thread.join()


def gather_person(ihunt: Ihunt) -> None:
    threads = []

    # ------------------------------------------------------------------------------
    # Execute AI-related APIs lastly from the perspective of accuracy
    # ------------------------------------------------------------------------------

    thread = threading.Thread(target=req_duckduckgo, args=(ihunt, lock, DataPerson))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.groq:
        thread = threading.Thread(target=req_groq, args=(ihunt, lock, DataPerson))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Groq API key is not set.", ihunt.verbose)

    for thread in threads:
        thread.join()


def gather_phone(ihunt: Ihunt) -> None:
    threads = []

    # ------------------------------------------------------------------------------
    # Execute AI-related APIs lastly from the perspective of accuracy
    # ------------------------------------------------------------------------------

    thread = threading.Thread(target=req_duckduckgo, args=(ihunt, lock, DataPhone))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.groq:
        thread = threading.Thread(target=req_groq, args=(ihunt, lock, DataPhone))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Groq API key is not set.", ihunt.verbose)

    for thread in threads:
        thread.join()


def gather_url(ihunt: Ihunt) -> None:
    threads = []

    if ihunt.apikeys.urldna:
        thread = threading.Thread(target=req_urldna_url, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] urlDNA API key is not set.", ihunt.verbose)

    if ihunt.apikeys.virustotal:
        thread = threading.Thread(target=req_virustotal_url, args=(ihunt, lock))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] VirusTotal API key is not set.", ihunt.verbose)

    # ------------------------------------------------------------------------------
    # Execute AI-related APIs lastly from the perspective of accuracy
    # ------------------------------------------------------------------------------

    thread = threading.Thread(target=req_duckduckgo, args=(ihunt, lock, DataUrl))
    threads.append(thread)
    thread.start()

    if ihunt.apikeys.groq:
        thread = threading.Thread(target=req_groq, args=(ihunt, lock, DataUrl))
        threads.append(thread)
        thread.start()
    else:
        echo("[x] Groq API key is not set.", ihunt.verbose)

    for thread in threads:
        thread.join()

    # Additional research
    if ihunt.data.dom is not None:
        # Find vulnerabilities of website via HTML (DOM) using LLM
        # ...
        pass


def gather(ihunt: Ihunt) -> None:
    echo("[*] Start gathering information...", ihunt.verbose)

    if ihunt.query.type == QueryType.DOMAIN:
        gather_domain(ihunt)
    elif ihunt.query.type == QueryType.EMAIL:
        gather_email(ihunt)
    elif ihunt.query.type == QueryType.HASH:
        gather_hash(ihunt)
    elif ihunt.query.type == QueryType.IP:
        gather_ip(ihunt)
    elif ihunt.query.type == QueryType.URL:
        gather_url(ihunt)
    elif ihunt.query.type == QueryType.ORG:
        gather_org(ihunt)
    elif ihunt.query.type == QueryType.PERSON:
        gather_person(ihunt)
    elif ihunt.query.type == QueryType.PHONE:
        gather_phone(ihunt)
    elif ihunt.query.type == QueryType.UNKNOWN:
        echo("[x] Query Type Unknown", ihunt.verbose)

    echo("[*] Fished gathering.", ihunt.verbose)
