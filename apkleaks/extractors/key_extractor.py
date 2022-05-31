import traceback
import base64
import os
import math

from tqdm import tqdm

from apkleaks.heuristics.entropy_calculator import EntropyCalculator
from apkleaks.heuristics.string_detection import StringDetection


SECRET_KEY_LENGTH = [128, 256, 512]

ENTROPY_MARGIN = 5.0
ENTROPY_FRACTURE_MARGIN = 0.04
HIGHEST_ENTROPY_VALUE = 4.5

SCORE_KEY_FOUND = 30
SCORE_MATCHING_IMPORTS = 20
SCORE_MATCHING_KEYWORD = 10

class KeyExtractor():
    def __init__(self):
        self._entropy_calculator = EntropyCalculator()
        self._string_detection = StringDetection()

    def extract_secret_key(self, key_extractor_pattern, sourcepath, total_files):
        found_secret_keys = self.file_reader(sourcepath, total_files)

        if found_secret_keys:
            key_extractor_pattern.results['possible_secrets'] = found_secret_keys

    # Prüft ob ein Regex Pattern mit dem Source Code match und so ein Secret offenbart
    def file_reader(self, path, total_files) -> list():
        found_matches = []
        progressbar = tqdm(total=total_files)
        for fp, _, files in os.walk(path):
            for fn in files:
                filepath = os.path.join(fp, fn)
                with open(filepath, errors='ignore') as handle:
                    progressbar.set_description("Key_Extractor: processing %s" % filepath)
                    try:
                        linenumber = 0
                        for line in handle.readlines():
                            entropy = self._entropy_calculator.calculate_shannon_entropy(line)
                            secret_key = self.contains_aes_key(line, entropy)
                            if secret_key:
                                self.oragnize_result(found_matches, secret_key, line, linenumber, filepath) 
                            linenumber += 1
                    except Exception:
                        print(traceback.format_exc())
                    
                    progressbar.update(1)

        return found_matches

    def contains_aes_key(self, line, entropy):
        if entropy > ENTROPY_MARGIN and entropy/len(line) > ENTROPY_FRACTURE_MARGIN:
            for key_length in SECRET_KEY_LENGTH:
                base64_key_length = 4*math.ceil(((key_length/8)/3))
                if base64_key_length%4==3:
                    base64_key_length+=1
                elif base64_key_length%4==2:
                    base64_key_length+=2
                elif base64_key_length%4==1:
                    base64_key_length+=3
                
                # sequenz_entropy_dict = self.sliding_window(base64_key_length, line)
                sequenz_entropy_dict = self._string_detection.detect_string(line, sequence_length=base64_key_length)
                
                if sequenz_entropy_dict:
                    return sequenz_entropy_dict

        return False

    def decrypt_base64(self, sequence):
        #Checks if sequence is base64 encoded
        try:
            line_bytes = bytes(sequence, 'utf-8')
            processed_line_sequence = base64.decodebytes(line_bytes)
            return processed_line_sequence
        # Catches exception if sequence is not in base64 format and returns false.
        except:
            return False

    def oragnize_result(self, found_matches, found_secret, line, linenumber, filepath) -> list():
        for found_match in found_matches:
            if found_match['secret'] == found_secret:
                found_match['line_content'].append(line)
                found_match['linenumbers'].append(linenumber)
                found_match['filepaths'].append(filepath)
        
                return
        
        result = {
            'secret': found_secret,
            'line_content': [line,],
            'linenumbers': [linenumber,],
            'filepaths': [filepath,]
        }

        found_matches.append(result)
        	
