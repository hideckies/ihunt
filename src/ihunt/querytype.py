from duckduckgo_search import DDGS
from enum import Enum
import re
# from .apis.duckduckgo import req_duckduckgo_querytype
from .stdout import echo
from .utils import is_ip_address


# Search models: https://huggingface.co/models?pipeline_tag=token-classification
model_ner = "dslim/bert-base-NER"
# model_ner = "dbmdz/bert-large-cased-finetuned-conll03-english"


class QueryType(Enum):
    DOMAIN  = 1
    EMAIL   = 2
    FILE    = 3
    HASH    = 4
    IP      = 5
    ORG     = 6
    PERSON  = 7
    TEL     = 8
    URL     = 9
    UNKNOWN = 10


# The function is used for detecting query type.
def identify_querytype_with_duckduckgo(query: str, verbose: bool) -> QueryType:
    echo("[*] Detecting the query type with DuckDuckGo API...", verbose)
    prompt = f"""
Which of the following types can the text "{query}" be categorized into? Please answer just the category type.

File Path
Hash
Organization
Person
TEL
Unknown
"""
    try:
        results = DDGS().chat(f"{prompt}", model='claude-3-haiku')
        if results.lower() == "file path":
            return QueryType.FILE
        elif results.lower() == "hash":
            return QueryType.HASH
        elif results.lower() == "organization":
            return QueryType.ORG
        elif results.lower() == "person":
            return QueryType.PERSON
        elif results.lower() == "tel":
            return QueryType.TEL
        else:
            return QueryType.UNKNOWN
    except Exception as e:
         echo(f"[x] DuckDuckGo API error: {e}", verbose)
         return QueryType.UNKNOWN


# Uses LLM NER task.
def identify_querytype_with_huggingface(query: str) -> QueryType:
    import torch
    from transformers import pipeline
    device = (
        "cuda"
        if torch.cuda.is_available()
        else "mps"
        if torch.backends.mps.is_available()
        else "cpu"
    )
    ner = pipeline(task="ner", model=model_ner, device=device)
    entities = ner(query)
    
    if len(entities) == 0:
        return QueryType.UNKNOWN

    for entity in entities:
        entity_type = entity['entity']
        if "-ORG" in entity_type:
            return QueryType.ORG
        elif "-PER" in entity_type:
            return QueryType.PERSON
        else:
            return QueryType.UNKNOWN


def identify_querytype(query: str, verbose: bool) -> QueryType:
    echo("[*] Identifying the query type...", verbose)

    # If it was not detected by DuckDuckGo, try programatically resolutions.
    domain_pattern = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)?(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    url_pattern = re.compile(r'^(https?|ftp|ssh)://[^\s/$.?#].[^\s]*$', re.IGNORECASE)

    if domain_pattern.match(query):
        return QueryType.DOMAIN
    elif email_pattern.match(query):
        return QueryType.EMAIL
    elif is_ip_address(query):
        return QueryType.IP
    elif url_pattern.match(query):
        return QueryType.URL
    
    # Try DuckDuckGo Chat API.
    query_type = identify_querytype_with_duckduckgo(query, verbose)
    if query_type != QueryType.UNKNOWN:
        return query_type

    # Try HuggingFace API.
    return identify_querytype_with_huggingface(query)


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
        elif self.type == QueryType.FILE:
            return "File"
        elif self.type == QueryType.HASH:
            return "Hash"
        elif self.type == QueryType.IP:
            return "IP"
        elif self.type == QueryType.ORG:
            return "Organization"
        elif self.type == QueryType.PERSON:
            return "Person"
        elif self.type == QueryType.TEL:
            return "TEL"
        elif self.type == QueryType.URL:
            return "URL"
        elif self.type == QueryType.UNKNOWN:
            return "Unknown"


