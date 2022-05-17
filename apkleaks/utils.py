#!/usr/bin/env python3
import os
import re
import sys
import math
import traceback
import math
import base64

from pyrsistent import field

from apkleaks.colors import color as col
from apkleaks.library_extraction import LibraryExtraction

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
	def quotes_indicator(line, base64_key_length=0, no_key_length=False):
		sequenz_entropy_dict = dict()
		for i in range(len(line)):
				line_quote_sequence = line[i:i+1]
				if line_quote_sequence == "\"":
					if no_key_length == True or i+base64_key_length+1 < len(line) and line[i+base64_key_length+1:i+base64_key_length+2] == "\"":
						
						begin_line_sequence = i+1
						end_line_sequence = begin_line_sequence

						if no_key_length == True:
							for x in range(i+1, (i+1)+len(line[i+1:])):
								if line[x:x+1] == "\"":
									end_line_sequence = x

									break
						else:
							end_line_sequence = i+base64_key_length+1
					

						line_sequence = line[begin_line_sequence:end_line_sequence]
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


	@staticmethod
	def calculate_shannon_entropy(string):
		"""
		Calculates the Shannonx entropy for the given string.

		:param string: String to parse.
		:type string: str

		:returns: Shannon entropy (min bits per byte-character).
		:rtype: float
		"""
		ent = 0.0
		if len(string) < 2:
			return ent
		size = float(len(string))
		freq = dict()
		for char in string:
			if char in freq:
				freq[char] = freq[char] + 1
			else:
				freq[char] = 1

		for value in freq.values():		
			if value > 0:
				prop = float(value) / size
				ent = ent + prop * math.log(1/prop, 2)
		return ent
