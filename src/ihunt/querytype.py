from duckduckgo_search import DDGS
from enum import Enum
import re
import threading
from .stdout import echo, spinner
from .utils import is_ip_address


class QueryType(Enum):
    DOMAIN  = 1
    EMAIL   = 2
    HASH    = 3
    IP      = 4
    ORG     = 5
    PERSON  = 6
    PHONE   = 7
    URL     = 8
    UNKNOWN = 9


# The function is used for detecting query type.
def identify_querytype_with_duckduckgo(query: str, verbose: bool) -> QueryType:
    echo("[*] Detecting the query type with DuckDuckGo API...", verbose)
    prompt = f"""
Which of the following types can the text "{query}" be categorized into? Please answer just the category type.

Hash
Organization
Person
Phone number
Unknown
"""
    try:
        results = DDGS().chat(f"{prompt}", model='claude-3-haiku')
        if results.lower() == "hash":
            return QueryType.HASH
        elif results.lower() == "organization":
            return QueryType.ORG
        elif results.lower() == "person":
            return QueryType.PERSON
        elif results.lower() == "phone number":
            return QueryType.PHONE
        else:
            return QueryType.UNKNOWN
    except Exception as e:
         echo(f"[x] DuckDuckGo API error: {e}", verbose)
         return QueryType.UNKNOWN


def identify_querytype(query: str, verbose: bool) -> QueryType:
    echo("[*] Identifying the query type...", verbose)

    done = threading.Event()

    t = threading.Thread(target=spinner, args=(done, "Identifying the query type..."))
    t.start()

    # If it was not detected by DuckDuckGo, try programatically resolutions.
    domain_pattern = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)?(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    url_pattern = re.compile(r'^(https?|ftp|ssh)://[^\s/$.?#].[^\s]*$', re.IGNORECASE)

    if domain_pattern.match(query):
        done.set()
        t.join()
        return QueryType.DOMAIN
    elif email_pattern.match(query):
        done.set()
        t.join()
        return QueryType.EMAIL
    elif is_ip_address(query):
        done.set()
        t.join()
        return QueryType.IP
    elif url_pattern.match(query):
        done.set()
        t.join()
        return QueryType.URL
    
    # Try DuckDuckGo Chat API.
    query_type = identify_querytype_with_duckduckgo(query, verbose)

    done.set()
    t.join()

    return query_type


class Query:
    value: str
    type: QueryType

    def __init__(self, value: str, verbose: bool) -> None:
        self.value = value
        self.type = identify_querytype(value, verbose)

    def type_str(self) -> str:
        if self.type == QueryType.DOMAIN:
            return "Domain"
        elif self.type == QueryType.EMAIL:
            return "Email"
        elif self.type == QueryType.HASH:
            return "Hash"
        elif self.type == QueryType.IP:
            return "IP"
        elif self.type == QueryType.ORG:
            return "Organization"
        elif self.type == QueryType.PERSON:
            return "Person"
        elif self.type == QueryType.PHONE:
            return "Phone"
        elif self.type == QueryType.URL:
            return "URL"
        elif self.type == QueryType.UNKNOWN:
            return "Unknown"


