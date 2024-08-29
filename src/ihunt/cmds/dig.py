import re
import subprocess
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty


# Query: Domain
# Return: Subdomains
def exec_dig_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo("[*] Executing dig command...", ihunt.verbose)

    result = subprocess.run(['dig', '+short', ihunt.query.value], capture_output=True, text=True)
    lines = result.stdout.splitlines()

    try:
        with lock:
            for line in lines:
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line):
                    if is_empty(ihunt.data.ips):
                        ihunt.data.ips = [line]
                    else:
                        if line not in ihunt.data.ips:
                            ihunt.data.ips.append(line)
    except Exception as e:
        echo(f"[x] dig command error: {e}", ihunt.verbose)

    echo("[*] Finished executing dig command.", ihunt.verbose)
