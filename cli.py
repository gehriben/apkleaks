#!/usr/bin/env python3
import logging
import click
import isg.logging

from isg.config import Config
from apk_scanner.scan import Scan
from data_analysis.data_analyser import DataAnalyser
from data_analysis.data_visualisation import DataVisualisation
from apkleaks.heuristics.endpoint_validation import EndpointValidation

app_config = Config('config.yml', namespace='HDV')
log_path = app_config['paths']['logs']
debug = app_config['logging']['debug']
silent = app_config['logging']['silent']

@click.group()
def apk_scanner_cli():
    pass

@apk_scanner_cli.command()
def start_apk_scan():
    try:
        isg.logging.init_logging('apk-scanner', app_config['paths']['logs'],
                                    base_level=logging.DEBUG if debug else logging.INFO, silent=silent)
        scan = Scan()
        scan.start_scan()
    except:
        logging.exception('Error running apk-scanner')
        logging.disable(logging.CRITICAL)

@apk_scanner_cli.command()
def start_data_analysis():
    try:
        isg.logging.init_logging('apk-scanner', app_config['paths']['logs'],
                                    base_level=logging.DEBUG if debug else logging.INFO, silent=silent)
        data_analyser = DataAnalyser()
        data_analyser.start_analysis()
    except:
        logging.exception('Error running apk-scanner')
        logging.disable(logging.CRITICAL)

@apk_scanner_cli.command()
def start_data_visualisation():
    try:
        isg.logging.init_logging('apk-scanner', app_config['paths']['logs'],
                                    base_level=logging.DEBUG if debug else logging.INFO, silent=silent)
        data_visualiser = DataVisualisation()
        data_visualiser.start_visualistaion()
    except:
        logging.exception('Error running apk-scanner')
        logging.disable(logging.CRITICAL)


@apk_scanner_cli.command()
def idle():
    while True:
        pass
    
@apk_scanner_cli.command()
def do_nothing():
    # pass
    endpoint_validation = EndpointValidation()
    # print(endpoint_validation.search_for_valid_endpoint("AIzaSyBXffDrv5b4RWmyFylQzwoumN5VpHwPpEU"))
    print(endpoint_validation.search_for_valid_endpoint("AIzaSyBEpEwdBClM8koty10dj7n1QtVd75BaV9U"))

cli = click.CommandCollection(sources=[apk_scanner_cli])

if __name__ == '__main__':
    cli()