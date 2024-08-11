# # Docs: https://urlscan.io/docs/api/

import requests

# BASE_URL = "https://urlscan.io/api/v1/search"


# # Query: Domain
# # Return: Info
# def req_urlscan_domain(domain: str, apikey: str) -> None:
#     url = BASE_URL + f"/?q=domain:{domain}&size=100"
#     headers = {
#         'API-KEY': apikey,
#     }
#     resp = requests.get(url, headers=headers)

#     if resp.status_code == 200:
#         data = resp.json()
#         results = data["results"]
#         if len(results) == 0:
#             return None
        
#         for result in results:
#             task = result["task"]
#             page = result["page"]
#             print(f"task: {task}")
#             print(f"page: {page}")
#             break

#         return None
#     else:
#         return None
