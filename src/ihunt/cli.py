import click
from dotenv import load_dotenv
import os
import re
from .gather import gather
from .models import Ihunt
from .querytype import Query, QueryType
from .version import VERSION


@click.command()
@click.option('-c', '--config', help='Config file.')
@click.option('-f', '--format', type=click.Choice(['json', 'pretty', 'yaml']), default='json', help='Print format.')
@click.option('-o', '--output', help='Write results to the output file path.')
@click.option('-t', '--timeout', default=10, help='Timeout for fetching APIs.')
@click.option('-u', '--user-agent', default='ihunt (https://github.com/hideckies/ihunt)', help='Custome User-Agent used when fetching APIs')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output.')
@click.version_option(VERSION, prog_name="ihunt")
@click.argument('query')
def run(config: str, format: str, output: str, timeout: int, user_agent: str, verbose: bool, query: str) -> None:
    if config is not None:
        # Load configurations from file.
        if os.path.exists(config) is False:
            click.echo(f"[x] The config file does not exist: {config}")
            return
        load_dotenv(config)

    query = re.sub(r'\s+', ' ', query).strip()

    ihunt = Ihunt(
        query=Query(value=query, verbose=verbose),
        format=format,
        output=output,
        timeout=timeout,
        user_agent=user_agent,
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