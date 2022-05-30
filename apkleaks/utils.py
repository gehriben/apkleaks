#!/usr/bin/env python3
import os
import re
import sys
import math
import traceback
import math
import base64

from apkleaks.colors import color as col
from apkleaks.filter.library_extraction import LibraryExtraction

ALLOWED_FILE_EXTENSIONS = [
	'.java',
	'.xml'
]

SPECIAL_FILE_EXTENSIONS = [
	'.so'
]

BLOCKED_PATTERNS = [
	'DEFCON_CTF_Flag',
	'HackerOne_CTF_Flag',
	'HackTheBox_CTF_Flag',
	'JSON_Web_Token',
	'Authorization_Basic'
]

EXCLUDED_FILES = [
	'AndroidManifest.xml'
]

class util:
	@staticmethod
	def write(message, color):
		sys.stdout.write("%s%s%s" % (color, message, col.ENDC))

	@staticmethod
	def writeln(message, color):
		util.write(message + "\n", color)

	@staticmethod
	def sliding_window(secquence_length, line):
		sequenz_entropy_dict = dict()
		for i in range(len(line)):
			if i+secquence_length < len(line):
				line_sequence = line[i:i+secquence_length]
				processed_line_sequence = line_sequence
				#Checks if sequence is base64 encoded
				try:
					line_bytes = bytes(line_sequence, 'utf-8')
					processed_line_sequence = base64.decodebytes(line_bytes)
				# Throws an exception if sequence is not in base64 format. The exception will be ignored.
				except:
					pass
				# Continue with normal procedure if not
				finally:
					entropy_line_sequence = util.calculate_shannon_entropy(processed_line_sequence)
					sequenz_entropy_dict[line_sequence] = entropy_line_sequence


		return sequenz_entropy_dict

	@staticmethod
	def check_file(filepath, patternname):
		if util.is_file_excluded(filepath):
			return False, filepath
		
		if util.is_file_special(filepath, patternname):
			library_extraction = LibraryExtraction()
			filepath = library_extraction.start_decompiling(filepath)
			return True, filepath

		if not util.is_file_extension_allowed(filepath):
			return False, filepath

		return True, filepath

	@staticmethod
	def is_file_excluded(filepath):
		for excluded_file in EXCLUDED_FILES:
			if excluded_file in filepath:
				return True
		
		return False

	@staticmethod
	def is_file_extension_allowed(filepath):
		for allowed_file_extension in ALLOWED_FILE_EXTENSIONS:
			if filepath.endswith(allowed_file_extension):
				return True

		return False
	
	def is_file_special(filepath, patternname):
		for special_file_extension in SPECIAL_FILE_EXTENSIONS:
			if filepath.endswith(special_file_extension):
				for blocked_pattern in BLOCKED_PATTERNS:
					if patternname == blocked_pattern:
						return False
				
				return True
		
		return False
