#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

import pkg_resources

from apkleaks.apkleaks import APKLeaks
from apkleaks.colors import color as col

def header():
	try:
		VERSION = "v" + pkg_resources.require("apkleaks")[0].version
	except Exception:
		VERSION = open(os.path.join(str(Path(__file__).parent.parent), "VERSION"), "r").read().strip()
	print(col.HEADER + "     _    ____  _  ___               _        \n    / \\  |  _ \\| |/ / |    ___  __ _| | _____ \n   / _ \\ | |_) | ' /| |   / _ \\/ _` | |/ / __|\n  / ___ \\|  __/| . \\| |__|  __/ (_| |   <\\__ \\\n /_/   \\_\\_|   |_|\\_\\_____\\___|\\__,_|_|\\_\\___/\n {}\n --\n Scanning APK file for URIs, endpoints & secrets\n (c) 2020-2021, dwisiswant0\n".format(VERSION) + col.ENDC, file=sys.stderr)

def argument():
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--file", help="APK file to scanning", type=str, required=True)
	parser.add_argument("-o", "--output", help="Write to file results (random if not set)", type=str, required=False)
	parser.add_argument("-p", "--pattern", help="Path to custom patterns JSON", type=str, required=False)
	parser.add_argument("-a", "--args", help="Disassembler arguments (e.g. --threads-count 5 --deobf)", type=str, required=False)
	parser.add_argument("-v", "--verbose", help="Activates verbose mode. Needs path to store decompiled files", type=str, required=False)
	parser.add_argument("--pattern_matcher", help="Activates pattern_matcher", required=False, action="store_true")
	parser.add_argument("--key_extractor", help="Activates key_extractor", required=False, action="store_true")
	parser.add_argument("--credentials_extractor", help="Activates credentials_extractor", required=False, action="store_true")
	parser.add_argument("--json", help="Save as JSON format", required=False, action="store_true")
	
	arg = parser.parse_args()
	return arg

def main():
	header()
	args = argument()
	apkleaks = APKLeaks(args)
	try:
		apkleaks.initialization()
		apkleaks.scanning()
	finally:
		apkleaks.cleanup()
