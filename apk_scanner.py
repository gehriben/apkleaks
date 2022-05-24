#!/usr/bin/env python3
import click

from apk_scanner.scan import Scan


@click.group()
def apk_scanner_cli():
    pass


@apk_scanner_cli.command()
def evaluate():
    scan = Scan()
    scan.start_scan()



@apk_scanner_cli.command()
def idle():
    pass

cli = click.CommandCollection(sources=[apk_scanner_cli])

if __name__ == '__main__':
    cli()