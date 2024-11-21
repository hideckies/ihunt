import click
from colorama import Fore, Style
import itertools
import sys
from threading import Event
import time
from typing import Any


def echo(message: Any, verbose: bool) -> None:
    if verbose:
        click.echo(message)


spinner_chars = itertools.cycle(['|', '/', '-', '\\'])


def spinner(done: Event, text: str) -> None:
    text = f" {text}"

    while not done.is_set():
        sys.stdout.write(Fore.CYAN + next(spinner_chars) + text + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b' * (len(text) + 1)) # Move the cursor back

    # When finishing, delete the symbol and text.
    sys.stdout.write('\b' * (len(text) + 1))
    sys.stdout.write(' ' * (len(text) + 1))
    sys.stdout.write('\b' * (len(text) + 1))
    sys.stdout.flush()
    