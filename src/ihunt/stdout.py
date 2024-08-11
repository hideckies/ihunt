import click
from typing import Any


def echo(message: Any, verbose: bool) -> None:
    if verbose:
        click.echo(message)
