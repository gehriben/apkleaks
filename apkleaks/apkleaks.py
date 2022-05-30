#!/usr/bin/env python3
import io
import json
import logging.config
import os
import re
import shutil
import sys
import tempfile
import threading
import importlib

from distutils.spawn import find_executable
from pathlib import Path
from pipes import quote
from urllib.request import urlopen
from apkleaks.extractors.pattern_matcher import PatternMatcher
                                                                                                                                                                                                                                                                                                               
from apkleaks.colors import color as col
from apkleaks.utils import util
from apkleaks.decompiler import Decompiler
from apkleaks.filter.file_filtering import FileFiltering
from apkleaks.heuristics.heuristics import Heuristics
from apkleaks.scoring.scoring import Scoring
from apkleaks.scoring.secret_fiter import SecretFilter
from apkleaks.scoring.secret_fiter import RESTRICTIONS
from apkleaks.extractors.key_extractor import KeyExtractor
from apkleaks.extractors.credentials_extractor import CredentialsExtractor
from apkleaks.patterns.custom_pattern import CustomPattern
from apkleaks.patterns.key_extractor_pattern import KeyExtractorPattern
from apkleaks.patterns.credential_extractor_pattern import CredentialExtractorPattern


EXCLUDED_PATTERN_FILENAMES = [
	'__init__.py',
	'custom_pattern.py',
	'pattern.py',
	'key_extractor_pattern.py',
	'credential_extractor_pattern.py'
]

EXCLUDED_PATTERN_FILEPATHS = [
	'__pycache__'
]

class APKLeaks:
	def __init__(self, args, file=None, verbose=None, json=None, disarg=None, output=None, pattern=None, 
	pattern_matcher=False, key_extractor=False, credentials_extractor=False):
		self.file = os.path.realpath(args.file) if args else file
		self.verbose = args.verbose if args else verbose
		self.json = args.json if args else json
		self.disarg = args.args if args else disarg
		self.args_output = args.output if args else output
		self.args_pattern = args.pattern if args else pattern
		self.args_pattern_matcher = pattern_matcher
		self.args_key_extractor = key_extractor
		self.args_credentials_extractor = credentials_extractor
		self.prefix = "apkleaks-"
		self.tempdir = tempfile.mkdtemp(prefix=self.prefix) if not self.verbose else self.verbose
		self.main_dir = os.path.dirname(os.path.realpath(__file__))
		self.output = tempfile.mkstemp(suffix=".%s" % ("json" if self.json else "txt"), prefix=self.prefix)[1] if self.args_output is None else self.args_output
		self.fileout = open(self.output, "%s" % ("w" if self.json else "a"))
		self.pattern = os.path.join(str(Path(self.main_dir).parent), "config", "regexes.json") if self.args_pattern is None else self.args_pattern
		self.patterns = list()
		self.out_json = {}
		self.total_files = 0

		self._decompiler = Decompiler(self.file, self.tempdir)
		self._file_filtering = FileFiltering(self.tempdir)
		self._pattern_matcher = PatternMatcher()
		self._key_extractor = KeyExtractor()
		self._credential_extractor = CredentialsExtractor()
		self._heuristics = Heuristics()

		logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})

	def initialization(self):
		self._decompiler.decompile()
		self.total_files = self._file_filtering.filter_files()
		self.patterns = self.init_patterns()

	def init_patterns(self):
		patterns = list()

		count = 0
		for filepath, _, files in os.walk('apkleaks/patterns'):
			for filename in files:
				if self.is_pattern_valid(filename, filepath):
					module = importlib.import_module('.'+filename.replace(".py", ""), 'apkleaks.patterns')
					
					class_name = ""
					for word in filename.replace(".py","").split("_"):
						class_name += word.capitalize()
					
					class_ = getattr(module, class_name)
					patterns.append(class_())

		# Custom Patterns
		"""with open(self.pattern) as regexes:
			regex = json.load(regexes)
			for name, pattern in regex.items():
				if isinstance(pattern, list):
					custom_pattern = CustomPattern(name, pattern)
				else:
					pattern_list = list()
					pattern_list.append(pattern)
					custom_pattern = CustomPattern(name, pattern_list)
			
				patterns.append(custom_pattern)"""

		return patterns
	
	def scanning(self):
		if self._decompiler.apk is None:
			sys.exit(util.writeln("** Undefined package. Exit!", col.FAIL))
		util.writeln("\n** Scanning against '%s'" % (self._decompiler.apk.package), col.OKBLUE)
		self.out_json["package"] = self._decompiler.apk.package
		self.out_json["results"] = []

		if self.args_pattern_matcher == False and self.args_key_extractor == False and self.args_credentials_extractor == False:
			self.args_pattern_matcher == True
			self.args_key_extractor == True
			self.args_credentials_extractor == True

		if self.args_pattern_matcher:
			scan_threads = list()
			for pattern in self.patterns:
				# print(pattern)
				# Prüft ob das Pattern eine Liste ist oder nicht und verarbeitet es entsprechend
				try:
					thread = threading.Thread(target = self.extract, args = (pattern,))
					thread.start()
					scan_threads.append(thread)
				except KeyboardInterrupt:
					sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

		if self.args_key_extractor:
			#Try to extract aes key with entropy based searcher
			try:
				thread_aes_key_extractor = threading.Thread(target = self.extract_secret_key)
				thread_aes_key_extractor.start()
			except KeyboardInterrupt:
				sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

		if self.args_credentials_extractor:
			#Try to extract credentials key with keyword based searcher
			try:
				thread_credentials_extractor = threading.Thread(target = self.extract_credentials)
				thread_credentials_extractor.start()
			except KeyboardInterrupt:
				sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))
		
		if self.args_pattern_matcher:
			for scan_thread in scan_threads:
				scan_thread.join()

		if self.args_key_extractor:
			thread_aes_key_extractor.join()
		if self.args_credentials_extractor:	
			thread_credentials_extractor.join()

	def extract(self, pattern):
		print(f"--- Search for pattern {pattern.name} ---")
		self._pattern_matcher.search_pattern_matches(pattern, self.tempdir)
		self._heuristics.apply_heuristics(pattern)

		scoring = Scoring()
		scoring.do_scoring(pattern)

		secret_filter = SecretFilter()
		secret_filter.filter_secrets(RESTRICTIONS.MEDIUM, pattern)
		
		self.output_results(pattern)
		# print(f"--- {pattern.name} ---")
		# print(pattern.results)

	def extract_secret_key(self):
		print(f"--- Search for Secret Keys ---")
		_key_extractor_pattern = KeyExtractorPattern()
		self._key_extractor.extract_secret_key(_key_extractor_pattern, self.tempdir)
		self._heuristics.apply_heuristics(_key_extractor_pattern)

		scoring = Scoring()
		scoring.do_scoring(_key_extractor_pattern)

		secret_filter = SecretFilter()
		secret_filter.filter_secrets(RESTRICTIONS.MEDIUM, _key_extractor_pattern)
		
		self.output_results(_key_extractor_pattern)

	def extract_credentials(self):
		print(f"--- Search for Credentials ---")
		_credential_extractor_pattern = CredentialExtractorPattern()
		self._credential_extractor.search_credentials(_credential_extractor_pattern, self.tempdir, self.total_files)
		self._heuristics.apply_heuristics(_credential_extractor_pattern)

		scoring = Scoring()
		scoring.do_scoring(_credential_extractor_pattern)

		secret_filter = SecretFilter()
		secret_filter.filter_secrets(RESTRICTIONS.MEDIUM, _credential_extractor_pattern)
		
		self.output_results(_credential_extractor_pattern)

	def output_results(self, pattern):
		if 'valid_secrets' in pattern.results:
			stdout = ("[%s]" % (pattern.name))
			util.writeln("\n" + stdout, col.OKGREEN)
			self.fileout.write("%s" % (stdout + "\n" if self.json is False else ""))
			for valid_secrets in pattern.results['valid_secrets']:
				stdout = ("- %s (score: %s)" % (valid_secrets['secret'], valid_secrets['score']))
				print(stdout)
				self.fileout.write("%s" % (stdout + "\n" if self.json is False else ""))
			self.fileout.write("%s" % ("\n" if self.json is False else ""))

			self.out_json["results"].append(pattern.json())	
			"""print("")
			stdout = ("[%s]" % ('JSON_Printout'))
			util.writeln("\n" + stdout, col.OKGREEN)
			print(stdout)
			print(self.out_json)"""
	
	def is_pattern_valid(self, filename, filepath):
		for excluded_pattern_filename in EXCLUDED_PATTERN_FILENAMES:
			if excluded_pattern_filename == filename:
				return False

		for excluded_pattern_filepaths in EXCLUDED_PATTERN_FILEPATHS:
			if filepath.endswith(excluded_pattern_filepaths):
				return False

		return True

	def cleanup(self):
		if not self.verbose:
			shutil.rmtree(self.tempdir)

		self.fileout.write("%s" % (json.dumps(self.out_json, indent=4) if self.json else ""))
		self.fileout.close()
		print("%s\n** Results saved into '%s%s%s%s'%s." % (col.HEADER, col.ENDC, col.OKGREEN, self.output, col.HEADER, col.ENDC))
		"""if self.scanned and self.scanned_for_aes and self.scanned_for_credentials:
			self.fileout.write("%s" % (json.dumps(self.out_json, indent=4) if self.json else ""))
			self.fileout.close()
			print("%s\n** Results saved into '%s%s%s%s'%s." % (col.HEADER, col.ENDC, col.OKGREEN, self.output, col.HEADER, col.ENDC))
		else:
			self.fileout.close()
			os.remove(self.output)
			util.writeln("\n** Done with nothing. ¯\\_(ツ)_/¯", col.WARNING)"""
