from enum import Enum

class RESTRICTIONS(Enum):
    LOW = 0
    MEDIUM = 1/3
    HIGH = 2/3

class SecretFilter():
    def __init__(self):
        pass
    
    def filter_secrets(self, filter_mode, pattern):
        valid_secrets = list()
        for secret in pattern.results['pattern_matcher']:
            if self.__is_found_secret_valid(filter_mode, secret):
                valid_secrets.append({'secret': secret['secret'], 'score': secret['total_score']})

        self.pattern.results['valid_secrets'] = valid_secrets
    
    def __is_found_secret_valid(self, filter_mode, secret):
        score = secret['total_score'].split('/')  
        if score[0] >= filter_mode*score[1]:
            return True
        else:
            return False