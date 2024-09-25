import subprocess
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

CMD = "whois"


# Query: Domain
# Return: Info
def exec_whois_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Executing {CMD} command...", ihunt.verbose)

    try:
        result = subprocess.run([CMD, ihunt.query.value], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        with lock:
            for line in lines:
                if ':' not in line:
                    continue
                key, val = map(str.strip, line.split(':', 1))
                if key == "Domain Name" and is_empty(ihunt.data.domain):
                    ihunt.data.domain = val
                if key == "Updated Date" and is_empty(ihunt.data.updated_date):
                    ihunt.data.updated_date = val
                if key == "Creation Date" and is_empty(ihunt.data.creation_date):
                    ihunt.data.creation_date = val
                if key == "Registry Expiry Date" and is_empty(ihunt.data.registry_expiry_date):
                    ihunt.data.registry_expiry_date = val
                if key == "Registrar" and is_empty(ihunt.data.registrar_name):
                    ihunt.data.registrar_name = val
                if key == "Registrar IANA ID" and is_empty(ihunt.data.registrar_iana_id):
                    ihunt.data.registrar_iana_id = val
                if key == "Domain Status":
                    if is_empty(ihunt.data.status):
                        ihunt.data.status = [val]
                    else:
                        if val not in ihunt.data.status:
                            ihunt.data.status.append(val)
                if key == "Registrant Name" and is_empty(ihunt.data.registrant_name):
                    ihunt.data.registrant_name = val
                if key == "Registrant Organization" and is_empty(ihunt.data.registrant_organization):
                    ihunt.data.registrant_organization = val
                if key == "Registrant Street" and is_empty(ihunt.data.registrant_street):
                    ihunt.data.registrant_street = val
                if key == "Registrant City" and is_empty(ihunt.data.registrant_city):
                    ihunt.data.registrant_city = val
                if key == "Registrant State/Province" and is_empty(ihunt.data.registrant_state):
                    ihunt.data.registrant_state = val
                if key == "Registrant Postal Code" and is_empty(ihunt.data.registrant_postal_code):
                    ihunt.data.registrant_postal_code = val
                if key == "Registrant Country" and is_empty(ihunt.data.registrant_country):
                    ihunt.data.registrant_country = val
                if key == "Registrant Phone" and is_empty(ihunt.data.registrant_phone):
                    ihunt.data.registrant_phone = val
                if key == "Registrant Fax" and is_empty(ihunt.data.registrant_fax):
                    ihunt.data.registrant_fax = val
                if key == "Registrant Email" and is_empty(ihunt.data.registrant_email):
                    ihunt.data.registrant_email = val
                if key == "Admin Name" and is_empty(ihunt.data.admin_name):
                    ihunt.data.admin_name = val
                if key == "Admin Organization" and is_empty(ihunt.data.admin_organization):
                    ihunt.data.admin_organization = val
                if key == "Admin Street" and is_empty(ihunt.data.admin_street):
                    ihunt.data.admin_street = val
                if key == "Admin City" and is_empty(ihunt.data.admin_city):
                    ihunt.data.admin_city = val
                if key == "Admin State/Province" and is_empty(ihunt.data.admin_state):
                    ihunt.data.admin_state = val
                if key == "Admin Postal Code" and is_empty(ihunt.data.admin_postal_code):
                    ihunt.data.admin_postal_code = val
                if key == "Admin Country" and is_empty(ihunt.data.admin_country):
                    ihunt.data.admin_country = val
                if key == "Admin Phone" and is_empty(ihunt.data.admin_phone):
                    ihunt.data.admin_phone = val
                if key == "Admin Fax" and is_empty(ihunt.data.admin_fax):
                    ihunt.data.admin_fax = val
                if key == "Admin Email" and is_empty(ihunt.data.admin_email):
                    ihunt.data.admin_email = val
                if key == "Tech Name" and is_empty(ihunt.data.tech_name):
                    ihunt.data.tech_name = val
                if key == "Tech Organization" and is_empty(ihunt.data.tech_organization):
                    ihunt.data.tech_organization = val
                if key == "Tech Street" and is_empty(ihunt.data.tech_street):
                    ihunt.data.tech_street = val
                if key == "Tech City" and is_empty(ihunt.data.tech_city):
                    ihunt.data.tech_city = val
                if key == "Tech State/Province" and is_empty(ihunt.data.tech_state):
                    ihunt.data.tech_state = val
                if key == "Tech Postal Code" and is_empty(ihunt.data.tech_postal_code):
                    ihunt.data.tech_postal_code = val
                if key == "Tech Country" and is_empty(ihunt.data.tech_country):
                    ihunt.data.tech_country = val
                if key == "Tech Phone" and is_empty(ihunt.data.tech_phone):
                    ihunt.data.tech_phone = val
                if key == "Tech Fax" and is_empty(ihunt.data.tech_fax):
                    ihunt.data.tech_fax = val
                if key == "Tech Email" and is_empty(ihunt.data.tech_email):
                    ihunt.data.tech_email = val
                if key == "Name Server":
                    if is_empty(ihunt.data.name_servers):
                        ihunt.data.name_servers = [val]
                    else:
                        if val not in ihunt.data.name_servers:
                            ihunt.data.name_servers.append(val)
                if key == "DNSSEC":
                    ihunt.data.dnssec = val
    except Exception as e:
        echo(f"[x] {CMD} command error: {e}", ihunt.verbose)

    echo("[*] Finished executing {CMD} command.", ihunt.verbose)


# Query: IP
# Return: Info
def exec_whois_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Executing {CMD} command...", ihunt.verbose)

    try:
        result = subprocess.run([CMD, ihunt.query.value], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        with lock:
            for line in lines:
                if ':' not in line or '%' in line:
                    continue
                key, val = map(str.strip, line.split(':', 1))
                if key == "inetnum" and is_empty(ihunt.data.net_range):
                    ihunt.data.net_range = val
                if key == "netname" and is_empty(ihunt.data.net_name):
                    ihunt.data.net_name = val
                if key == "descr" and is_empty(ihunt.data.net_desc):
                    ihunt.data.net_desc = val
                if key == "country" and is_empty(ihunt.data.country_code):
                    ihunt.data.country_code = val
                if key == "admin-c":
                    if is_empty(ihunt.data.net_admin_handle):
                        ihunt.data.net_admin_handle = val
                    # Additional information for the admin-c
                    result = subprocess.run([CMD, val], capture_output=True, text=True)
                    lines_2 = result.stdout.splitlines()
                    for line_2 in lines_2:
                        if ':' not in line_2 or '%' in line_2:
                            continue
                        key_2, val_2 = map(str.strip, line_2.split(':', 1))
                        if key_2 == "role" and is_empty(ihunt.data.net_admin_role):
                            ihunt.data.net_admin_role = val_2
                        if key_2 == "person":
                            if is_empty(ihunt.data.net_admin_persons):
                                ihunt.data.net_admin_persons = [val_2]
                            else:
                                ihunt.data.net_admin_persons.append(val_2)
                if key == "tech-c":
                    if is_empty(ihunt.data.net_tech_handle):
                        ihunt.data.net_tech_handle = val
                    # Additional information for the tech-c
                    result = subprocess.run([CMD, val], capture_output=True, text=True)
                    line_2 = result.stdout.splitlines()

                    for line_2 in lines_2:
                        if ':' not in line_2 or '%' in line_2:
                            continue
                        key_2, val_2 = map(str.strip, line_2.split(':', 1))
                        if key_2 == "role" and is_empty(ihunt.data.net_tech_role):
                            ihunt.data.net_tech_role = val_2
                        if key_2 == "person":
                            if is_empty(ihunt.data.net_tech_persons):
                                ihunt.data.net_tech_persons = [val_2]
                            else:
                                ihunt.data.net_tech_persons.append(val_2)
    except Exception as e:
        echo(f"[x] {CMD} command error: {e}", ihunt.verbose)

    echo(f"[*] Finished executing {CMD} command.", ihunt.verbose)
