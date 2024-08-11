# from huggingface_hub import login
# from threading import Lock
# from transformers import pipeline
# from ..models import Ihunt
# from ..stdout import echo

# # Query: Organization
# # Return: The organization7s summary
# def req_huggingface_org(ihunt: Ihunt, lock: Lock) -> None:
#     echo("[*] Fetching Hugging Face...", ihunt.verbose)

#     login(token=ihunt.apikeys.huggingface)

#     pipe = pipeline(
#         "text-generation", model="distilbert/distilgpt2")

#     content = f"""
# Please tell me information about {ihunt.query.value}. The format is below:

# - name
# - description
# - founded_year
# - address
# - country_name
# - country_code
# - region
# - state
# - city
# - postal_code
# - latitude
# - longitude
# - emails
# - faxes
# - phones
# - domains
# - websites
# - ceo
# """

#     outputs = pipe(content, max_new_tokens=256)
#     print(outputs)

#     with lock:
#         pass

#     echo("[*] Finished fetching Hugging Face.", ihunt.verbose)