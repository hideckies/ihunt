# # Docs: https://developer.shodan.io/api

# from dataclasses import dataclass
# import requests

# BASE_URL = "https://api.shodan.io"


# # Query: Domain
# # Return: Info
# def req_shodan_domain(domain: str, apikey: str) -> None:
#     url = BASE_URL + f"/dns/domain/{domain}?key={apikey}"
#     resp = requests.get(url)
#     if resp.status_code == 200:
#         data = resp.json()
#         d_data : list[dict[str, str]]  = data["data"]
#         subdomains: list[Subdomain] = []
#         for d in d_data:
#             subdomains.append(
#                 Subdomain(
#                     domain=d["subdomain"],
#                     type=d["type"],
#                     value=d["value"],
#                     last_seen=d["last_seen"],
#                 )
#             )
#         # return ShodanDomainResponse(
#         #     domain=data["domain"],
#         #     subdomains=subdomains,
#         # )
#         return None
#     else:
#         return None


# # Query: IP
# # Return: Info
# def req_shodan_ip(ip: str, apikey: str) -> None:
#     url = BASE_URL + f"/host/{ip}?key={apikey}"
#     resp = requests.get(url)
#     data = resp.json()
#     if resp.status_code == 200:
#         # return ShodanIpResponse(
#         #     region_code=data["region_code"],
#         #     ip=data["ip"],
#         #     postal_code=data["postal_code"],
#         #     country_code=data["country_code"],
#         #     city=data["city"],
#         #     dma_code=data["dma_code"],
#         #     last_update=data["last_update"],
#         #     latitude=data["latitude"],
#         #     tags=data["tags"],
#         #     area_code=data["are_code"],
#         #     country_name=data["country_name"],
#         #     hostnames=data["hostnames"],
#         #     org=data["org"],
#         #     asn=data["asn"],
#         #     isp=data["isp"],
#         #     longitude=data["longitude"],
#         #     country_code3=data["country_code3"],
#         #     domains=data["domains"],
#         #     ip_str=data["ip_str"],
#         #     os=data["os"],
#         #     ports=data["ports"],
#         # )
#         return None
#     else:
#         return None

