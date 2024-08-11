import re
from .models import QueryType
from .stdout import echo
from .utils import is_ip_address


# Search models: https://huggingface.co/models?pipeline_tag=token-classification
model_ner = "dslim/bert-base-NER"
# model_ner = "dbmdz/bert-large-cased-finetuned-conll03-english"
    

# Uses LLM NER task.
def identify_entity(query: str) -> QueryType:
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
            return QueryType.MISC


def identify_querytype(query: str, verbose: bool) -> QueryType:
    echo("[*] Identifying the query type...", verbose)

    url_pattern = re.compile(r'^(https?|ftp|ssh)://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    domain_pattern = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)?(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    if domain_pattern.match(query):
        return QueryType.DOMAIN
    elif email_pattern.match(query):
        return QueryType.EMAIL
    elif is_ip_address(query):
        return QueryType.IP
    elif url_pattern.match(query):
        return QueryType.URL
    else:
        # Identify it using LLM
        return identify_entity(query)
