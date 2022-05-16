import traceback
import os

from apkleaks.utils import util
from apkleaks.import_extractor import ImportExtractor
from apkleaks.keyword_searcher import CREDENTIALS_KEYWORDS, KeywordSearcher
from apkleaks.score import Score
from apkleaks.score import Scoremargin

ENTROPY_MARGIN = 4.0
ENTROPY_FRACTURE_MARGIN = 0.4
HIGHEST_ENTROPY_VALUE = 3.5

SCORE_CREDENTIAL_FOUND = 20
SCORE_MATCHING_KEYWORD = 20

class CredentialsExtractor():
    def __init__(self):
        self._keyword_searcher = KeywordSearcher()

    def extract_credentials(self, path):
        found_credentials = list()
        for fp, _, files in os.walk(path):
            for fn in files:
                filepath = os.path.join(fp, fn)
                with open(filepath, errors='ignore') as handle:
                    try:
                        for line in handle.readlines():       
                            credentials_keywords = self._keyword_searcher.search_credentials_keywords(line)
                            if len(credentials_keywords) != 0:
                                credentials = self.contains_credentails(line)
                                for credential,entropy in credentials.items():
                                    if  credential not in found_credentials and credential != '':
                                        credential_score = Score(Scoremargin.AES, credential)
                                        credential_score.increase_score(SCORE_CREDENTIAL_FOUND)

                                        credential_score.increase_score(SCORE_MATCHING_KEYWORD*len(credentials_keywords))

                                        if credential_score.is_margin_reached():
                                            keywords = ', '.join(str(e) for e in credentials_keywords)
                                            credential = keywords + ": " + credential
                                            found_credentials.append(credential)
                    except Exception:
                        print(traceback.format_exc())
        
        print(found_credentials)
        return found_credentials

    def contains_credentails(self, line):
        # sequenz_entropy_dict = self.sliding_window(line, no_key_length=True)
        sequenz_entropy_dict = util.quotes_indicator(line, no_key_length=True)

        return sequenz_entropy_dict
