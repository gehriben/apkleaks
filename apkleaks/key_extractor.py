import traceback
import base64
import os
import math

from apkleaks.utils import util
from apkleaks.import_extractor import ImportExtractor
from apkleaks.keyword_searcher import KeywordSearcher
from apkleaks.score import Score
from apkleaks.score import Scoremargin

SECRET_KEY_LENGTH = [128, 256, 512]

ENTROPY_MARGIN = 5.0
ENTROPY_FRACTURE_MARGIN = 0.04
HIGHEST_ENTROPY_VALUE = 4.5

SCORE_KEY_FOUND = 30
SCORE_MATCHING_IMPORTS = 20
SCORE_MATCHING_KEYWORD = 10

class KeyExtractor():
    def __init__(self):
        self._import_extractor = ImportExtractor()
        self._keyword_searcher = KeywordSearcher()

    def extract_aes_key(self, path, fileout, verbose):
        found_aes_keys = list()
        for fp, _, files in os.walk(path):
            for fn in files:
                filepath = os.path.join(fp, fn)
                if not util.is_file_excluded(filepath) and util.is_file_extension_allowed(filepath):
                    with open(filepath, errors='ignore') as handle:
                        try:
                            for line in handle.readlines():
                                entropy = util.calculate_shannon_entropy(line)
                                aes_key = self.contains_aes_key(line, entropy, fp+'/'+fn)

                                if aes_key != False and aes_key not in found_aes_keys:
                                    aes_key_score = Score(Scoremargin.AES, aes_key)
                                    aes_key_score.increase_score(SCORE_KEY_FOUND)
                                    
                                    if self._import_extractor.check_crypto_imports(filepath):
                                        aes_key_score.increase_score(SCORE_MATCHING_IMPORTS)

                                    if self._keyword_searcher.search_aes_keywords(filepath):
                                        aes_key_score.increase_score(SCORE_MATCHING_KEYWORD)

                                    if aes_key_score.is_margin_reached():
                                        if verbose:
                                            fileout.write("%s/%s" % (fp, fn + "\n"))
                                        found_aes_keys.append(aes_key)
                        except Exception:
                            print(traceback.format_exc())

        return found_aes_keys

    def contains_aes_key(self, line, entropy, path):
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
                sequenz_entropy_dict = util.quotes_indicator(line, base64_key_length=base64_key_length)

                highest_entropy_value = 0.0
                highest_entropy_key = ""

                for key, value in sequenz_entropy_dict.items():
                    if value > highest_entropy_value:
                        highest_entropy_value = value
                        highest_entropy_key = key

                if highest_entropy_value > HIGHEST_ENTROPY_VALUE: 
                    """print("==> AES KEY FOUND: "+str(highest_entropy_key)+" WITH "+str(highest_entropy_value)+" ENTROPY AND LENGTH OF "+str(key_length)+" Bits!")
                    print("    --> Found in line: "+line)
                    print("    --> Found in document: "+path)"""
                    return highest_entropy_key

        return False	
