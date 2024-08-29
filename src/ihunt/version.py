import click

VERSION = "0.1.4"


def print_version(ctx, param, value) -> None:
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"ihunt v{VERSION}")
    ctx.exit()