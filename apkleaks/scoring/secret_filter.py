from enum import Enum

class RESTRICTIONS(Enum):
    NONE = -1
    LOW = 2
    MEDIUM = 1
    HIGH = 0

class SecretFilter():
    def __init__(self):
        pass
    
    def filter_secrets(self, filter_mode, pattern):
        valid_secrets = list()
        index = 0
        if 'possible_secrets' in pattern.results:
            for secret in pattern.results['possible_secrets']:
                if self.__is_found_secret_valid(filter_mode, secret, pattern):
                    valid_secrets.append({'secret': secret['secret'], 'index': index, 'score': secret['total_score']})
                
                index += 1

            if valid_secrets:
                pattern.results['valid_secrets'] = valid_secrets
    
    def __is_found_secret_valid(self, filter_mode, secret, pattern):
        score = secret['total_score'].split('/')
        if float(self.__calculate_score(score, filter_mode.value, pattern)) >= float(score[1]):
            return True
        else:
            return False
    
    def __calculate_score(self, score, C, pattern):
        if C != RESTRICTIONS.NONE:
            return float(score[0]) + float(C/pattern.get_heuristic_amount()) * float(score[1])
        else:
            return float(score[0]) + float(score[1])