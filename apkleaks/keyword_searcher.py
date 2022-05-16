import traceback

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
    def __init__(self):
        pass

    def search_aes_keywords(self, filepath):
        if len(self.search_keywords_in_file(filepath, AES_KEYWORDS)) != 0:
            return True
        else:
            return False
    
    def search_credentials_keywords(self, line):
        return self.search_keywords_in_line(line, CREDENTIALS_KEYWORDS)

    def search_keywords_in_file(self, filepath, keywords):
        found_keywords = list()
        
        with open(filepath, errors='ignore') as handle:
            try:
                for line in handle.readlines():
                    for keyword in keywords:
                        if keyword.lower() in line.lower():
                            found_keywords.append(keyword.lower())
            except Exception:
                print(traceback.format_exc())
        

        return found_keywords

    def search_keywords_in_line(self, line, keywords):
        found_keywords = list()
        
        for keyword in keywords:
            if keyword.lower() in line.lower():
                found_keywords.append(keyword.lower())

        return found_keywords

        