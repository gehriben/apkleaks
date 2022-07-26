import traceback
import os

from tqdm import tqdm

from apkleaks.utils import util
from apkleaks.heuristics.keyword_searcher import KeywordSearcher
from apkleaks.heuristics.string_detection import StringDetection

ENTROPY_MARGIN = 4.0
ENTROPY_FRACTURE_MARGIN = 0.4
HIGHEST_ENTROPY_VALUE = 3.5

SCORE_CREDENTIAL_FOUND = 20
SCORE_MATCHING_KEYWORD = 20

CREDENTIALS_KEYWORDS = [
    '.*[p|P][a|A][s|S][s|S][w|W][o|O][r|R][d|D].*[=].*',
    '[p|P][a|A][s|S][s|S][ ]?[=].*',
]

EXCLUDED_FILE_EXTENSIONS = [
	'.so.txt',
    '.dex'
]

class CredentialsExtractor():
    def __init__(self):
        self._keyword_searcher = KeywordSearcher(CREDENTIALS_KEYWORDS)
        self._string_detection = StringDetection()

    def search_credentials(self, credentials_extractor_pattern, sourcepath, total_files):        
        found_credentials = self.file_reader(sourcepath, total_files)

        if found_credentials:
            credentials_extractor_pattern.results['possible_secrets'] = found_credentials

    def file_reader(self, path, total_files) -> list():
        found_credentials = []
        progressbar = tqdm(total=total_files)
        for fp, _, files in os.walk(path):
            for fn in files:
                filepath = os.path.join(fp, fn)
                if not self.check_if_file_is_excluded(filepath):
                    with open(filepath, errors='ignore') as handle:
                        progressbar.set_description("Credentials_Extractor: processing %s" % filepath)
                        try:
                            linenumber = 0
                            for line in handle.readlines():
                                line_with_possible_credentials = self._keyword_searcher.search_keywords_in_line(line)
                                if line_with_possible_credentials:
                                    self.extract_credentails(found_credentials, line_with_possible_credentials, line, linenumber, filepath)
                                linenumber += 1
                        except Exception:
                            print(traceback.format_exc())
                        
                        progressbar.update(1)

        return found_credentials

    def extract_credentails(self, found_credentials, line_with_possible_credentials, line, linenumber, filepath):
        possible_credentials = self._string_detection.detect_string(line_with_possible_credentials, no_length=True)
        if possible_credentials:
            self.oragnize_result(found_credentials, possible_credentials, line, linenumber, filepath)
    
    def oragnize_result(self, found_credentials, found_secret, line, linenumber, filepath) -> list():
        for found_match in found_credentials:
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

        found_credentials.append(result)
    
    def check_if_file_is_excluded(self, filepath):
        for excluded_file_extension in EXCLUDED_FILE_EXTENSIONS:
            if filepath.endswith(excluded_file_extension):
                return True

        return False
