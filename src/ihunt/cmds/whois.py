import subprocess
from threading import Lock
from ..models import Ihunt
from ..stdout import echo


# Query: Domain
# Return: Info
def exec_whois_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Executing whois command...", ihunt.verbose)

    result = subprocess.run(['whois', ihunt.query.value], capture_output=True, text=True)
    lines = result.stdout.splitlines()

    try:
        with lock:
            for line in lines:
                if ':' not in line:
                    continue
                key, val = map(str.strip, line.split(':', 1))
                if key == "Domain Name" and ihunt.data.domain is None:
                    ihunt.data.domain = val
                if key == "Updated Date" and ihunt.data.updated_date is None:
                    ihunt.data.updated_date = val
                if key == "Creation Date" and ihunt.data.creation_date is None:
                    ihunt.data.creation_date = val
                if key == "Registry Expiry Date" and ihunt.data.registry_expiry_date is None:
                    ihunt.data.registry_expiry_date = val
                if key == "Registrar" and ihunt.data.registrar_name is None:
                    ihunt.data.registrar_name = val
                if key == "Registrar IANA ID" and ihunt.data.registrar_iana_id is None:
                    ihunt.data.registrar_iana_id = val
                if key == "Domain Status":
                    if ihunt.data.status is None:
                        ihunt.data.status = [val]
                    else:
                        if val not in ihunt.data.status:
                            ihunt.data.status.append(val)
                if key == "Registrant Name" and ihunt.data.registrant_name is None:
                    ihunt.data.registrant_name = val
                if key == "Registrant Organization" and ihunt.data.registrant_organization is None:
                    ihunt.data.registrant_organization = val
                if key == "Registrant Street" and ihunt.data.registrant_street is None:
                    ihunt.data.registrant_street = val
                if key == "Registrant City" and ihunt.data.registrant_city is None:
                    ihunt.data.registrant_city = val
                if key == "Registrant State/Province" and ihunt.data.registrant_state is None:
                    ihunt.data.registrant_state = val
                if key == "Registrant Postal Code" and ihunt.data.registrant_postal_code is None:
                    ihunt.data.registrant_postal_code = val
                if key == "Registrant Country" and ihunt.data.registrant_country is None:
                    ihunt.data.registrant_country = val
                if key == "Registrant Phone" and ihunt.data.registrant_phone is None:
                    ihunt.data.registrant_phone = val
                if key == "Registrant Fax" and ihunt.data.registrant_fax is None:
                    ihunt.data.registrant_fax = val
                if key == "Registrant Email" and ihunt.data.registrant_email is None:
                    ihunt.data.registrant_email = val
                if key == "Admin Name" and ihunt.data.admin_name is None:
                    ihunt.data.admin_name = val
                if key == "Admin Organization" and ihunt.data.admin_organization is None:
                    ihunt.data.admin_organization = val
                if key == "Admin Street" and ihunt.data.admin_street is None:
                    ihunt.data.admin_street = val
                if key == "Admin City" and ihunt.data.admin_city is None:
                    ihunt.data.admin_city = val
                if key == "Admin State/Province" and ihunt.data.admin_state is None:
                    ihunt.data.admin_state = val
                if key == "Admin Postal Code" and ihunt.data.admin_postal_code is None:
                    ihunt.data.admin_postal_code = val
                if key == "Admin Country" and ihunt.data.admin_country is None:
                    ihunt.data.admin_country = val
                if key == "Admin Phone" and ihunt.data.admin_phone is None:
                    ihunt.data.admin_phone = val
                if key == "Admin Fax" and ihunt.data.admin_fax is None:
                    ihunt.data.admin_fax = val
                if key == "Admin Email" and ihunt.data.admin_email is None:
                    ihunt.data.admin_email = val
                if key == "Tech Name" and ihunt.data.tech_name is None:
                    ihunt.data.tech_name = val
                if key == "Tech Organization" and ihunt.data.tech_organization is None:
                    ihunt.data.tech_organization = val
                if key == "Tech Street" and ihunt.data.tech_street is None:
                    ihunt.data.tech_street = val
                if key == "Tech City" and ihunt.data.tech_city is None:
                    ihunt.data.tech_city = val
                if key == "Tech State/Province" and ihunt.data.tech_state is None:
                    ihunt.data.tech_state = val
                if key == "Tech Postal Code" and ihunt.data.tech_postal_code is None:
                    ihunt.data.tech_postal_code = val
                if key == "Tech Country" and ihunt.data.tech_country is None:
                    ihunt.data.tech_country = val
                if key == "Tech Phone" and ihunt.data.tech_phone is None:
                    ihunt.data.tech_phone = val
                if key == "Tech Fax" and ihunt.data.tech_fax is None:
                    ihunt.data.tech_fax = val
                if key == "Tech Email" and ihunt.data.tech_email is None:
                    ihunt.data.tech_email = val
                if key == "Name Server":
                    if ihunt.data.name_servers is None:
                        ihunt.data.name_servers = [val]
                    else:
                        if val not in ihunt.data.name_servers:
                            ihunt.data.name_servers.append(val)
                if key == "DNSSEC":
                    ihunt.data.dnssec = val
    except Exception as e:
        echo(f"[x] whois command error: {e}", ihunt.verbose)

    echo("[*] Finished executing whois command.", ihunt.verbose)


# Query: IP
# Return: Info
def exec_whois_ip(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Executing whois command...", ihunt.verbose)

    result = subprocess.run(['whois', ihunt.query.value], capture_output=True, text=True)
    lines = result.stdout.splitlines()

    try:
        with lock:
            for line in lines:
                if ':' not in line or '%' in line:
                    continue
                key, val = map(str.strip, line.split(':', 1))
                if key == "inetnum" and ihunt.data.net_range is None:
                    ihunt.data.net_range = val
                if key == "netname" and ihunt.data.net_name is None:
                    ihunt.data.net_name = val
                if key == "descr" and ihunt.data.net_desc is None:
                    ihunt.data.net_desc = val
                if key == "country" and ihunt.data.country_code is None:
                    ihunt.data.country_code = val
                if key == "admin-c":
                    if ihunt.data.net_admin_handle is None:
                        ihunt.data.net_admin_handle = val
                    # Additional information for the admin-c
                    result = subprocess.run(['whois', val], capture_output=True, text=True)
                    lines_2 = result.stdout.splitlines()
                    for line_2 in lines_2:
                        if ':' not in line_2 or '%' in line_2:
                            continue
                        key_2, val_2 = map(str.strip, line_2.split(':', 1))
                        if key_2 == "role" and ihunt.data.net_admin_role is None:
                            ihunt.data.net_admin_role = val_2
                        if key_2 == "person":
                            if ihunt.data.net_admin_persons is None:
                                ihunt.data.net_admin_persons = [val_2]
                            else:
                                ihunt.data.net_admin_persons.append(val_2)
                if key == "tech-c":
                    if ihunt.data.net_tech_handle is None:
                        ihunt.data.net_tech_handle = val
                    # Additional information for the tech-c
                    result = subprocess.run(['whois', val], capture_output=True, text=True)
                    line_2 = result.stdout.splitlines()

                    for line_2 in lines_2:
                        if ':' not in line_2 or '%' in line_2:
                            continue
                        key_2, val_2 = map(str.strip, line_2.split(':', 1))
                        if key_2 == "role" and ihunt.data.net_tech_role is None:
                            ihunt.data.net_tech_role = val_2
                        if key_2 == "person":
                            if ihunt.data.net_tech_persons is None:
                                ihunt.data.net_tech_persons = [val_2]
                            else:
                                ihunt.data.net_tech_persons.append(val_2)
    except Exception as e:
        echo(f"[x] whois command error: {e}", ihunt.verbose)

    echo("[*] Finished executing whois command.", ihunt.verbose)
