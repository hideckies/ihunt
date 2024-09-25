import re
import subprocess
from threading import Lock
from ..models import Ihunt
from ..stdout import echo
from ..utils import is_empty

CMD = "dig"


# Query: Domain
# Return: Subdomains
def exec_dig_domain(ihunt: Ihunt, lock: Lock) -> None:
    echo(f"[*] Executing {CMD} command...", ihunt.verbose)

    try:
        result = subprocess.run([CMD, '+short', ihunt.query.value], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        with lock:
            for line in lines:
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line):
                    if is_empty(ihunt.data.ips):
                        ihunt.data.ips = [line]
                    else:
                        if line not in ihunt.data.ips:
                            ihunt.data.ips.append(line)
    except Exception as e:
        echo(f"[x] {CMD} command error: {e}", ihunt.verbose)

    echo(f"[*] Finished executing {CMD} command.", ihunt.verbose)
