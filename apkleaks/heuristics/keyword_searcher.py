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

CREDENTIALS_KEYWORDS = [
    'password',
    'pass',
    'username',
    'user',
    'nickname',
    'login',
    'email'
]

class KeywordSearcher():
    def __init__(self, filepaths, keyword_patterns):
        self.filepaths = filepaths
        self.keyword_patterns = keyword_patterns

    def search_keywords(self) -> dict():
        found_keywords = dict()
        try:
            for filepath in self.filepaths:
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

        