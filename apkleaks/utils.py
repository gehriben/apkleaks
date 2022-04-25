#!/usr/bin/env python3
import os
import re
import sys
import math
import traceback
import time
import base64
import math
from apkleaks.colors import color as col

SECRET_KEY_LENGTH = [128, 256, 512]

class util:
	@staticmethod
	def write(message, color):
		sys.stdout.write("%s%s%s" % (color, message, col.ENDC))

	@staticmethod
	def writeln(message, color):
		util.write(message + "\n", color)

	@staticmethod
	# Prüft ob ein Regex Pattern mit dem Source Code match und so ein Secret offenbart
	def finder(pattern, path, fileout):
		found = []
		count = 0
		for fp, _, files in os.walk(path):
			for fn in files:
				filepath = os.path.join(fp, fn)
				with open(filepath, errors='ignore') as handle:
					try:
						for line in handle.readlines():
							util.matcher(pattern, line, found, fp, fn, fileout)
					except Exception:
						print(traceback.format_exc())

		return sorted(list(set(found)))
	
	@staticmethod
	def matcher(pattern, line, found, fp, fn, fileout):
		matcher = re.compile(pattern)
		mo = matcher.search(line)
		if mo:
			# fileout.write("%s/%s" % (fp, fn + "\n"))
			found.append(mo.group())

	@staticmethod
	def get_aes_key(path):
		found_aes_keys = list()
		for fp, _, files in os.walk(path):
			for fn in files:
				filepath = os.path.join(fp, fn)
				with open(filepath, errors='ignore') as handle:
					try:
						for line in handle.readlines():
							#if fn == "MainActivity.java":
							entropy = util.calculate_shannon_entropy(line)
							aes_key = util.contains_aes_key(line, entropy, fp+'/'+fn)
							if aes_key != False and aes_key not in found_aes_keys:
								found_aes_keys.append(aes_key)
					except Exception:
						print(traceback.format_exc())

		print(found_aes_keys)
		return found_aes_keys

	@staticmethod
	def contains_aes_key(line, entropy, path):
		if entropy > 5.0 and entropy/len(line) > 0.04:
			for key_length in SECRET_KEY_LENGTH:
				base64_key_length = 4*math.ceil(((key_length/8)/3))
				if base64_key_length%4==3:
					base64_key_length+=1
				elif base64_key_length%4==2:
					base64_key_length+=2
				elif base64_key_length%4==1:
					base64_key_length+=3
				
				# sequenz_entropy_dict = util.sliding_window(base64_key_length, line)
				sequenz_entropy_dict = util.quotes_indicator(base64_key_length, line)

				highest_entropy_value = 0.0
				highest_entropy_key = ""

				for key, value in sequenz_entropy_dict.items():
					if value > highest_entropy_value:
						highest_entropy_value = value
						highest_entropy_key = key

				if highest_entropy_value > 4.8: 
					"""print("==> AES KEY FOUND: "+str(highest_entropy_key)+" WITH "+str(highest_entropy_value)+" ENTROPY AND LENGTH OF "+str(key_length)+" Bits!")
					print("    --> Found in line: "+line)
					print("    --> Found in document: "+path)"""
					return highest_entropy_key

		return False	
	
	@staticmethod
	def sliding_window(base64_key_length, line):
		sequenz_entropy_dict = dict()
		for i in range(len(line)):
			if i+base64_key_length < len(line):
				line_sequence = line[i:i+base64_key_length]
				# print(str(i) + ": " + str(line_sequence))
				try:
					line_bytes = bytes(line_sequence, 'utf-8')
					# print("  --> Bytes: " + str(line_bytes))
					base64_decoded = base64.decodebytes(line_bytes)
					# print("  --> Base64 Decoded: " + str(base64_decoded))
					# print("  --> Length of Base64 Decoded: " + str(len(base64_decoded)))
					entropy_base64_decoded = util.calculate_shannon_entropy(base64_decoded)
					# print("  --> Base64 Decoded Entropy: " + str(entropy_base64_decoded))
					sequenz_entropy_dict[line_sequence] = entropy_base64_decoded
				except:
					# traceback.print_exc()
					pass
		
		return sequenz_entropy_dict
	
	@staticmethod
	def quotes_indicator(base64_key_length, line):
		sequenz_entropy_dict = dict()
		for i in range(len(line)):
				line_quote_sequence = line[i:i+1]
				if line_quote_sequence == "\"":
					# print(line[i+base64_key_length+1:i+base64_key_length+2])
					if i+base64_key_length+1 < len(line) and line[i+base64_key_length+1:i+base64_key_length+2] == "\"":
						line_sequence = line[i+1:i+base64_key_length+1]
						# print(str(i) + ": " + str(line_sequence))
						try:
							line_bytes = bytes(line_sequence, 'utf-8')
							# print("  --> Bytes: " + str(line_bytes))
							base64_decoded = base64.decodebytes(line_bytes)
							# print("  --> Base64 Decoded: " + str(base64_decoded))
							# print("  --> Length of Base64 Decoded: " + str(len(base64_decoded)))
							entropy_base64_decoded = util.calculate_shannon_entropy(base64_decoded)
							# print("  --> Base64 Decoded Entropy: " + str(entropy_base64_decoded))
							sequenz_entropy_dict[line_sequence] = entropy_base64_decoded
						except:
							# traceback.print_exc()
							pass
		
		return sequenz_entropy_dict	

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
