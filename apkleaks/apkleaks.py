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

from distutils.spawn import find_executable
from pathlib import Path
from pipes import quote
from urllib.request import urlopen

from pyaxmlparser import APK
                                                                                                                                                                                                                                                                                                               
from apkleaks.colors import color as col
from apkleaks.utils import util
from apkleaks.decompiler import Decompiler
from apkleaks.key_extractor import KeyExtractor
from apkleaks.credentials_extractor import CredentialsExtractor
from apkleaks.patterns.custom_pattern import CustomPattern

class APKLeaks:
	def __init__(self, args):
		self.apk = None
		self.file = os.path.realpath(args.file)
		self.verbose = args.verbose
		self.json = args.json
		self.disarg = args.args
		self.prefix = "apkleaks-"
		self.tempdir = tempfile.mkdtemp(prefix=self.prefix) if not self.verbose else self.verbose
		self.main_dir = os.path.dirname(os.path.realpath(__file__))
		self.output = tempfile.mkstemp(suffix=".%s" % ("json" if self.json else "txt"), prefix=self.prefix)[1] if args.output is None else args.output
		self.fileout = open(self.output, "%s" % ("w" if self.json else "a"))
		self.pattern = os.path.join(str(Path(self.main_dir).parent), "config", "regexes.json") if args.pattern is None else args.pattern
		self.patterns = list()
		self.out_json = {}
		self.scanned = False
		self.scanned_for_aes = False
		self.scanned_for_credentials = False

		self._decompiler = Decompiler(self.file, self.tempdir)
		self._key_extractor = KeyExtractor()
		self._credentials_extractor = CredentialsExtractor()

		logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})

	def initialization(self):
		self._decompiler.decompile()
		self.patterns = self.init_patterns()

	def init_patterns(self):
		patterns = list()

		# Custom Patterns
		with open(self.pattern) as regexes:
			regex = json.load(regexes)
			for name, pattern in regex.items():
				if isinstance(pattern, list):
					custom_pattern = CustomPattern(name, pattern)
				else:
					pattern_list = list()
					pattern_list.append(pattern)
					custom_pattern = CustomPattern(name, pattern_list)
			
				patterns.append(custom_pattern)

		return patterns



	def extract(self, name, matches):
		if len(matches):
			for secret in matches:
				if name == "LinkFinder":
					if re.match(r"^.(L[a-z]|application|audio|fonts|image|kotlin|layout|multipart|plain|text|video).*\/.+", secret) is not None:
						continue
					secret = secret[len("'"):-len("'")]



	def extract_aes_key(self, results):
		if len(results):
			stdout = ("[%s]" % ("AES Key"))
			util.writeln("\n" + stdout, col.OKGREEN)
			self.fileout.write("%s" % (stdout + "\n" if self.json is False else ""))
			for key in results:
				stdout = ("- %s" % (key))
				print(stdout)
				self.fileout.write("%s" % (stdout + "\n" if self.json is False else ""))
			self.fileout.write("%s" % ("\n" if self.json is False else ""))
			self.out_json["results"].append({"name": "aes", "matches": results})
			self.scanned_for_aes = True
	
	def extract_credentails(self, results):
		if len(results):
			stdout = ("[%s]" % ("Credentials"))
			util.writeln("\n" + stdout, col.OKGREEN)
			self.fileout.write("%s" % (stdout + "\n" if self.json is False else ""))
			for credentials in results:
				stdout = ("- %s" % (credentials))
				print(stdout)
				self.fileout.write("%s" % (stdout + "\n" if self.json is False else ""))
			self.fileout.write("%s" % ("\n" if self.json is False else ""))
			self.out_json["results"].append({"name": "credentails", "matches": results})
			self.scanned_for_credentials = True

	def scanning(self):
		if self.apk is None:
			sys.exit(util.writeln("** Undefined package. Exit!", col.FAIL))
		util.writeln("\n** Scanning against '%s'" % (self.apk.package), col.OKBLUE)
		self.out_json["package"] = self.apk.package
		self.out_json["results"] = []

		for pattern in self.patterns:
			# print(pattern)
			# Prüft ob das Pattern eine Liste ist oder nicht und verarbeitet es entsprechend
			try:
				thread = threading.Thread(target = self.extract, args = (pattern.name, util.finder(pattern, self.tempdir)))
				thread.start()
			except KeyboardInterrupt:
				sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

		#Try to extract aes key with entropy based searcher
		try:
			thread_aes_key_extractor = threading.Thread(target = self.extract_aes_key, args = (self._key_extractor.extract_aes_key(self.tempdir, self.fileout, self.verbose),))
			thread_aes_key_extractor.start()
		except KeyboardInterrupt:
			sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

		#Try to extract credentials key with keyword based searcher
		"""try:
			thread_credentials_extractor = threading.Thread(target = self.extract_credentails, args = (self._credentials_extractor.extract_credentials(self.tempdir),))
			thread_credentials_extractor.start()
		except KeyboardInterrupt:
			sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))"""
		
		thread_aes_key_extractor.join()
		# thread_credentials_extractor.join()

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
