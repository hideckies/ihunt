import click
from dotenv import load_dotenv
import os
import re
from .gather import gather
from .models import Query, QueryType, Ihunt
from .querytype import identify_querytype


def print_version(ctx, param, value) -> None:
    if not value or ctx.resilient_parsing:
        return
    version = "0.0.0"
    click.echo(f"ihunt v{version}")
    ctx.exit()


@click.command()
@click.option('-c', '--config', help='Config file.')
@click.option('-d', '--depth', type=click.IntRange(1, 3), default=1, help='Depth of information gathering.')
@click.option('-f', '--format', type=click.Choice(['json', 'pretty', 'yaml']), default='json', help='Print format.')
@click.option('-o', '--output', help='Write results to the output file path.')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output.')
@click.option('--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True, help='The version of the Ihunt.')
@click.argument('query')
def run(config: str, depth: int, format: str, output: str, verbose: bool, query: str) -> None:
    if config is not None:
        # Load configurations from file.
        if os.path.exists(config) is False:
            click.echo(f"[x] The config file does not exist: {config}")
            return
        load_dotenv(config)

    query = re.sub(r'\s+', ' ', query).strip()

    ihunt = Ihunt(
        query=Query(value=query, type=identify_querytype(query, verbose)),
        depth=depth,
        format=format,
        output=output,
        verbose=verbose,
    )
    ihunt.print_options()

    if ihunt.query.type == QueryType.UNKNOWN:
        click.echo(f"Unknown query type: {ihunt.query.value}")
        return

    gather(ihunt)

    if ihunt.output is None:
        ihunt.print_data()
    else:
        ihunt.write()


def main() -> int:
    run()
    return 0
