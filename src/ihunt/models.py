from __future__ import annotations
import click
from dataclasses import asdict, dataclass
from enum import Enum
import json
import os
from pprint import PrettyPrinter
from typing import Any
import yaml
from .stdout import echo


class QueryType(Enum):
    DOMAIN  = 1
    EMAIL   = 2
    IP      = 3
    URL     = 4
    # Misc types
    ORG     = 5
    PERSON  = 6
    MISC    = 7
    UNKNOWN = 8


@dataclass
class Query:
    value: str
    type: QueryType

    def type_str(self) -> str:
        if self.type == QueryType.DOMAIN:
            return "Domain"
        elif self.type == QueryType.EMAIL:
            return "Email"
        elif self.type == QueryType.IP:
            return "IP"
        elif self.type == QueryType.URL:
            return "URL"
        elif self.type == QueryType.ORG:
            return "Organization"
        elif self.type == QueryType.PERSON:
            return "Person"
        elif self.type == QueryType.MISC:
            return "Misc"
        elif self.type == QueryType.UNKNOWN:
            return "Unknown"
        

class ApiKeyEnvs(Enum):
    ABUSEIPDB = "IHUNT_APIKEY_ABUSEIPDB"
    HUGGINGFACE = "IHUNT_APIKEY_HUGGINGFACE"
    HUNTER = "IHUNT_APIKEY_HUNTER"
    SHODAN = "IHUNT_APIKEY_SHODAN"
    URLDNA = "IHUNT_APIKEY_URLDNA"
    URLSCAN = "IHUNT_APIKEY_URLSCAN"
    VIRUSTOTAL = "IHUNT_APIKEY_VIRUSTOTAL"
    WHOISXML = "IHUNT_APIKEY_WHOISXML"
        

@dataclass
class ApiKeys:
    abuseipdb: str | None = None
    huggingface: str | None = None
    hunter: str | None = None
    shodan: str | None = None
    urldna: str | None = None
    urlscan: str | None = None
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
    dnssec: str | None = None
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
    provider_name: str | None = None
    creation_date: str | None = None
    owner_name: str | None = None
    gibberish: bool | None = None
    disposable: bool | None = None
    webmail: bool | None = None
    mx_records: bool | None = None
    smtp_server: bool | None = None
    smtp_check: bool | None = None
    accept_all: bool | None = None
    block: bool | None = None
    spam: bool | None = None


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
    ports: list[int] | None = None
    is_tor: bool | None = None
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


@dataclass
class DataMisc:
    entity: str | None = None


def init_data(query: Query) -> DataDomain | DataEmail | DataIp | DataOrg | DataPerson | DataUrl:
    if query.type == QueryType.DOMAIN:
        return DataDomain(domain=query.value)
    elif query.type == QueryType.EMAIL:
        return DataEmail(email=query.value)
    elif query.type == QueryType.IP:
        return DataIp(ip=query.value)
    elif query.type == QueryType.ORG:
        return DataOrg(org=query.value)
    elif query.type == QueryType.PERSON:
        return DataPerson(person=query.value)
    elif query.type == QueryType.URL:
        return DataUrl(url=query.value)
    elif query.type == QueryType.MISC:
        return DataMisc(entity=query.value)


class Ihunt:
    def __init__(self, query: Query, depth: int, format: str, output: str, verbose: bool) -> None:
        self.query: Query = query
        self.depth: int = depth
        self.format: str = format
        self.output: str = output
        self.verbose: bool = verbose
        self.apikeys = ApiKeys(
            abuseipdb=os.getenv(ApiKeyEnvs.ABUSEIPDB.value),
            huggingface=os.getenv(ApiKeyEnvs.HUGGINGFACE.value),
            hunter=os.getenv(ApiKeyEnvs.HUNTER.value),
            shodan=os.getenv(ApiKeyEnvs.SHODAN.value),
            urldna=os.getenv(ApiKeyEnvs.URLDNA.value),
            urlscan=os.getenv(ApiKeyEnvs.URLSCAN.value),
            virustotal=os.getenv(ApiKeyEnvs.VIRUSTOTAL.value),
            whoisxml=os.getenv(ApiKeyEnvs.WHOISXML.value),
        )
        self.data = init_data(query)

    def print_options(self) -> None:
        options = f"""
+ Query         : {self.query.value}
+ Query Type    : {self.query.type_str()}
+ Depth         : {self.depth}
+ Format        : {self.format}
+ Output        : {self.output}
+ Verbose       : {self.verbose}
"""
        echo(options, self.verbose)
    
    def print_data(self) -> None:
        echo("[*] Results:\n", self.verbose)

        if self.format == "json":
            click.echo(json.dumps(asdict(self.data), indent=4))
        elif self.format == "pretty":
            click.echo(PrettyPrinter(indent=4).pformat(asdict(self.data)))
        elif self.format == "yaml":
            click.echo(yaml.dump(asdict(self.data), default_flow_style=False, indent=4))
        
    def write(self) -> None:
        echo(f"[*] Writing results to {self.output}...", self.verbose)
        with open(self.output, 'w') as f:
            output_ext = os.path.splitext(self.output)
            if output_ext[1] == ".json":
                f.write(json.dumps(asdict(self.data), indent=4))
            elif output_ext[1] == ".yaml" or output_ext[1] == ".yml":
                f.write(yaml.dump(asdict(self.data), default_flow_style=False, indent=4))
            else:
                f.write(PrettyPrinter(indent=4).pformat(asdict(self.data)))

