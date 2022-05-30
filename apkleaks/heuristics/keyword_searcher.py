import traceback
import re

AES_KEYWORDS = [
    'AES',
    'CBC',
    'PKCS5PADDING',
    'SecretKey',
    'Cipher',
    'doFinal'
]

class KeywordSearcher():
    def __init__(self, keyword_patterns):
        self.keyword_patterns = keyword_patterns

    def search_keywords(self, filepaths) -> dict():
        found_keywords = dict()
        try:
            for filepath in filepaths:
                with open(filepath, errors='ignore') as handle:
                    for line in handle.readlines():
                        for regex in self.keyword_patterns:
                            matcher = re.compile(regex)
                            result = matcher.search(line)
                            if result:
                                if filepath not in found_keywords:
                                    found_keywords[filepath] = dict()
                                
                                if regex not in found_keywords[filepath]:
                                    found_keywords[filepath][regex] = [line,]
                                else:
                                    found_keywords[filepath][regex].append(line) 
        except Exception:
            print(traceback.format_exc())

        return found_keywords

    def search_keywords_in_line(self, line):
        try:
            for regex in self.keyword_patterns:
                matcher = re.compile(regex)
                result = matcher.search(line)
                if result:
                    return line
        except Exception:
            print(traceback.format_exc())

        return False

        