from enum import Enum

class RESTRICTIONS(Enum):
    LOW = 0
    MEDIUM = 1/3
    HIGH = 2/3

class SecretFilter():
    def __init__(self, filter_mode, pattern):
        self.filter_mode = filter_mode
        self.pattern = pattern
    
    def filter_pattern(self):
        valid_secrets = list()
        for secret in self.pattern.results['pattern_matcher']:
            if self.__is_found_secret_valid():
                valid_secrets.append({'secret': secret['secret'], 'score': secret['total_score']})

        self.pattern.results['valid_secrets'] = valid_secrets
    
    def __is_found_secret_valid(self, secret):
        score = secret['total_score'].split('/')  
        if score[0] >= self.filter_mode*score[1]:
            return True
        else:
            return False