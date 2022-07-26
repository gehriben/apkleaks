#!/usr/bin/env python3
import logging
import click

from apk_scanner.scan import Scan

@click.group()
def apk_scanner_cli():
    pass

@apk_scanner_cli.command()
def init():
    try:
        scan = Scan()
        scan.initalization()
        print("Initalization done!")
    except:
        logging.exception('Error running apk-scanner')
        logging.disable(logging.CRITICAL)

@apk_scanner_cli.command()
def start_scan():
    try:
        scan = Scan()
        scan.start_scan()
    except:
        logging.exception('Error running apk-scanner')
        logging.disable(logging.CRITICAL)


@apk_scanner_cli.command()
def idle():
    while True:
        pass
    
@apk_scanner_cli.command()
def do_nothing():
    pass

cli = click.CommandCollection(sources=[apk_scanner_cli])

if __name__ == '__main__':
    cli()