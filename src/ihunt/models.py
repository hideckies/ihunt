from __future__ import annotations
import click
from dataclasses import asdict, dataclass
import json
import os
from pprint import PrettyPrinter
from typing import Any
import yaml
from .querytype import Query, QueryType
from .stdout import echo
from .utils import remove_null_values_in_dict
        

@dataclass
class ApiKeys:
    abuseipdb: str | None = None
    emailrep: str | None = None
    gemini: str | None = None
    groq: str | None = None
    haveibeenpwned: str | None = None
    hunter: str | None = None
    pulsedive: str | None = None
    urldna: str | None = None
    virustotal: str | None = None
    whoisxml: str | None = None


@dataclass
class DataDomain:
    domain: str | None = None
    status: list[str] | None = None
    availability: str | None = None
    ips: list[str] | None = None
    subdomains: list[str] | None = None
    updated_date: str | None = None
    creation_date: str | None = None
    registry_expiry_date: str | None = None
    registrar_name: str | None = None
    registrar_iana_id: str | None = None
    registrant_name: str | None = None
    registrant_organization: str | None = None
    registrant_desc: str | None = None
    registrant_industry: str | None = None
    registrant_country: str | None = None
    registrant_country_code: str | None = None
    registrant_state: str | None = None
    registrant_city: str | None = None
    registrant_street: str | None = None
    registrant_postal_code: str | None = None
    registrant_email: str | None = None
    registrant_fax: str | None = None
    registrant_phone: str | None = None
    registrant_twitter: str | None = None
    registrant_facebook: str | None = None
    registrant_linkedin: str | None = None
    registrant_instagram: str | None = None
    registrant_youtube: str | None = None
    admin_name: str | None = None
    admin_organization: str | None = None
    admin_state: str | None = None
    admin_country: str | None = None
    admin_country_code: str | None = None
    admin_city: str | None = None
    admin_street: str | None = None
    admin_postal_code: str | None = None
    admin_email: str | None = None
    admin_fax: str | None = None
    admin_phone: str | None = None
    tech_name: str | None = None
    tech_organization: str | None = None
    tech_country: str | None = None
    tech_country_code: str | None = None
    tech_state: str | None = None
    tech_city: str | None = None
    tech_street: str | None = None
    tech_postal_code: str | None = None
    tech_email: str | None = None
    tech_fax: str | None = None
    tech_phone: str | None = None
    name_servers: list[str] | None = None
    dns: dict[str, Any] | None = None
    dnssec: str | None = None
    ports: list[Any] | None = None
    protocols: list[str] | None = None
    technologies: list[str] | None = None
    http_headers: dict[str, Any] | None = None
    https_cert_signature_algorithm: str | None = None
    https_cert_signature: str | None = None
    emails: list[str] | None = None
    jarm: str | None = None
    virustotal_link: str | None = None
    virustotal_stats: dict[str, int] | None = None
    virustotal_analysis: dict[str, dict[str, str]] | None = None
    virustotal_votes: dict[str, int] | None = None


@dataclass
class DataEmail:
    email: str | None = None
    domain: str | None = None
    domain_exists: bool | None = None
    domain_reputation: str | None = None
    domain_new: bool | None = None
    provider_name: str | None = None
    free_provider: bool | None = None
    creation_date: str | None = None
    owner_name: str | None = None
    gibberish: bool | None = None
    disposable: bool | None = None
    deliverable: bool | None = None
    spoofable: bool | None = None
    dmarc_enforced: bool | None = None
    webmail: bool | None = None
    mx_records: bool | None = None
    smtp_server: bool | None = None
    smtp_check: bool | None = None
    accept_all: bool | None = None
    block: bool | None = None
    spam: bool | None = None
    suspicious: bool | None = None
    blacklisted: bool | None = None
    malicious_activity: bool | None = None
    malicious_activity_recent: bool | None = None
    credentials_leaked: bool | None = None
    credentials_leaked_recent: bool | None = None
    data_breach: bool | None = None


@dataclass
class DataHash:
    hash: str | None = None
    hashtype: str | None = None
    filetype: str | None = None
    filenames: list[str] | None = None
    filesize: int | None = None
    magic: Any | None = None
    sha1: str | None = None
    sha256: str | None = None
    md5: str | None = None
    tlsh: str | None = None
    ssdeep: str | None = None
    vhash: str | None = None
    telfhash: str | None = None
    elf_info: dict[str, Any] | None = None
    pe_info: dict[str, Any] | None = None
    virustotal_link: str | None = None
    virustotal_stats: dict[str, int] | None = None
    virustotal_analysis: dict[str, dict[str, str]] | None = None
    virustotal_votes: dict[str, int] | None = None


@dataclass
class DataIp:
    ip: str | None = None
    net_range: str | None = None
    net_name: str | None = None
    net_desc: str | None = None
    net_admin_handle: str | None = None
    net_admin_role: str | None = None
    net_admin_persons: list[str] | None = None
    net_tech_handle: str | None = None
    net_tech_role: str | None = None
    net_tech_persons: list[str] | None = None
    asn: Any | None = None
    asname: str | None = None
    organization: str | None = None
    whitelisted: bool | None = None
    country_code: str | None = None
    country_name: str | None = None
    region: str | None = None
    city: str | None = None
    postal_code: str | None = None
    latitude: str | None = None
    longitude: str | None = None
    timezone: str | None = None
    currency: str | None = None
    currency_name: str | None = None
    languages: list[str] | None = None
    usage_type: str | None = None
    isp: str | None = None
    domain: str | None = None
    hostnames: list[str] | None = None
    ports: list[Any] | None = None
    protocols: list[Any] | None = None
    technologies: list[Any] | None = None
    http_headers: dict[str, Any] | None = None
    is_tor: bool | None = None
    is_proxy: bool | None = None
    is_mobile: bool | None = None
    subdomains: list[DataDomain] | None = None
    https_cert_signature_algorithm: str | None = None
    https_cert_signature: str | None = None
    jarm: str | None = None
    virustotal_link: str | None = None
    virustotal_stats: dict[str, int] | None = None
    virustotal_analysis: dict[str, dict[str, str]] | None = None
    virustotal_votes: dict[str, int] | None = None
    

@dataclass
class DataOrg:
    organization: str | None = None
    desc: str | None = None
    founded_year: int | None = None
    address: str | None = None
    country_name: str | None = None
    country_code: str | None = None
    region: str | None = None
    state: str | None = None
    city: str | None = None
    postal_code: str | None = None
    latitude: str | None = None
    longitude: str | None = None
    emails: list[str] | None = None
    faxes: list[str] | None = None
    phones: list[str] | None = None
    domains: list[str] | None = None
    websites: list[str] | None = None
    ceo: str | None = None
    employees: list[str] | None = None
    services: list[str] | None = None
    parent_organization: str | None = None
    

@dataclass
class DataPerson:
    person: str | None = None
    full_name: str | None = None
    aliases: list[str] | None = None
    age: int | None = None
    gender: str | None = None
    nationality: str | None = None
    birth_date: str | None = None
    birth_place: str | None = None
    address: str | None = None
    prev_addresses: list[str] | None = None
    education: str | None = None
    occupation: str | None = None
    employment_history: str | None = None
    acquaintances: list[str] | None = None
    friends: list[str] | None = None
    family_members: str | None = None
    emails: list[str] | None = None
    faxes: list[str] | None = None
    phones: list[str] | None = None
    websites: list[str] | None = None
    social_accounts: dict[str, str] | None = None
    photos: list[Any] | None = None
    hobbies: list[str] | None = None
    languages: list[str] | None = None
    race: str | None = None
    hair_color: str | None = None
    height: str | None = None
    weight: str | None = None
    personality: str | None = None


@dataclass
class DataPhone:
    phone: str | None = None
    organization: str | None = None
    person: str | None = None
    address: str | None = None
    country_name: str | None = None
    country_code: str | None = None
    city: str | None = None
    region: str | None = None
    state: str | None = None
    postal_code: str | None = None
    latitude: str | None = None
    longitude: str | None = None
    malicious: Any | None = None
    whitelisted: bool | None = None


@dataclass
class DataUrl:
    url: str | None = None
    cert_issuer: str | None = None
    cert_subject: str | None = None
    cert_serial_number: str | None = None
    console_messages: list[dict[str, str]] | None = None
    cookies: list[dict[str, Any]] | None = None
    dom: str | None = None
    favicon: Any | None = None
    ip: str | None = None
    asn: Any | None = None
    isp: str | None = None
    organization: str | None = None
    country_name: str | None = None
    country_code: str | None = None
    region: str | None = None
    city:  str | None = None
    latitude: str | None = None
    longitude: str | None = None
    malicious: Any | None = None
    page: Any | None = None
    screenshot: Any | None = None
    technologies: list[Any] | None = None
    virustotal_link: str | None = None
    virustotal_stats: dict[str, int] | None = None
    virustotal_analysis: dict[str, dict[str, str]] | None = None
    virustotal_votes: dict[str, int] | None = None
    virustotal_threat_names: list[str] | None = None


def init_data(query: Query) -> Any:
    if query.type == QueryType.DOMAIN:
        return DataDomain(domain=query.value)
    elif query.type == QueryType.EMAIL:
        return DataEmail(email=query.value)
    elif query.type == QueryType.HASH:
        return DataHash(hash=query.value)
    elif query.type == QueryType.IP:
        return DataIp(ip=query.value)
    elif query.type == QueryType.ORG:
        return DataOrg(organization=query.value)
    elif query.type == QueryType.PERSON:
        return DataPerson(person=query.value)
    elif query.type == QueryType.PHONE:
        return DataPhone(phone=query.value)
    elif query.type == QueryType.URL:
        return DataUrl(url=query.value)
    

class Ihunt:
    def __init__(
        self,
        query: Query,
        format: str,
        output: str,
        timeout: int,
        user_agent: str,
        verbose: bool,
    ) -> None:
        self.query: Query = query
        self.format: str = format
        self.output: str = output
        self.timeout: int = timeout
        self.user_agent: str = user_agent
        self.verbose: bool = verbose
        self.apikeys = ApiKeys(
            abuseipdb=os.getenv("IHUNT_APIKEY_ABUSEIPDB"),
            emailrep=os.getenv("IHUNT_APIKEY_EMAILREP"),
            gemini=os.getenv("IHUNT_APIKEY_GEMINI"),
            groq=os.getenv("IHUNT_APIKEY_GROQ"),
            hunter=os.getenv("IHUNT_APIKEY_HUNTER"),
            pulsedive=os.getenv("IHUNT_APIKEY_PULSEDIVE"),
            urldna=os.getenv("IHUNT_APIKEY_URLDNA"),
            virustotal=os.getenv("IHUNT_APIKEY_VIRUSTOTAL"),
            whoisxml=os.getenv("IHUNT_APIKEY_WHOISXML"),
        )
        self.data = init_data(query)

    def print_options(self) -> None:
        options = f"""
+ Query         : {self.query.value}
+ Query Type    : {self.query.type_str()}
+ Format        : {self.format}
+ Timeout       : {self.timeout}
+ Output        : {self.output}
+ Verbose       : {self.verbose}
"""
        echo(options, self.verbose)
    
    def print_data(self) -> None:
        echo("[*] Results:\n", self.verbose)

        data = remove_null_values_in_dict(asdict(self.data))

        if self.format == "json":
            click.echo(json.dumps(data, indent=4))
        elif self.format == "pretty":
            click.echo(PrettyPrinter(indent=4).pformat(data))
        elif self.format == "yaml":
            click.echo(yaml.dump(data, default_flow_style=False, indent=4))
        
    def write(self) -> None:
        echo(f"[*] Writing results to {self.output}...", self.verbose)

        data = remove_null_values_in_dict(asdict(self.data))

        with open(self.output, 'w') as f:
            output_ext = os.path.splitext(self.output)
            if output_ext[1] == ".json":
                f.write(json.dumps(data, indent=4))
            elif output_ext[1] == ".yaml" or output_ext[1] == ".yml":
                f.write(yaml.dump(data, default_flow_style=False, indent=4))
            else:
                f.write(PrettyPrinter(indent=4).pformat(data))

