from enum import Enum

class RESTRICTIONS(Enum):
    LOW = 0
    MEDIUM = 2/3
    HIGH = 3/3

class SecretFilter():
    def __init__(self):
        pass
    
    def filter_secrets(self, filter_mode, pattern):
        valid_secrets = list()
        if 'possible_secrets' in pattern.results:
            for secret in pattern.results['possible_secrets']:
                if self.__is_found_secret_valid(filter_mode, secret):
                    valid_secrets.append({'secret': secret['secret'], 'score': secret['total_score']})

            if valid_secrets:
                pattern.results['valid_secrets'] = valid_secrets
    
    def __is_found_secret_valid(self, filter_mode, secret):
        score = secret['total_score'].split('/')
        if float(score[0]) >= filter_mode.value*float(score[1]):
            return True
        else:
            return False