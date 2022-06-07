from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additive_score_type import AdditiveScore

STANDARD_ENTROPY_SCORE = 10
STANDARD_PASSWORD_VALIDATION_SCORE = 10
STANDARD_IMPORTS_SCORE = 20
STANDARD_KEYWORDS_SCORE = 10
STANDARD_ENDPOINT_SCORE = 10
STANDARD_PING_SCORE = 10

class Pattern():
    def __init__(self, name, regexes, heuristic_entropy=False, heuristic_password=False, 
                heuristic_imports=False, heuristic_keywords=False, heuristic_endpoint=False, heuristic_ping=False):
        self.name = name
        self.regexes = regexes
        self.results = dict() # key = file path; value = found secret
        self.heuristics_status = {
            'entropy': heuristic_entropy, 
            'password_validation': heuristic_password, 
            'imports': heuristic_imports,
            'keywords': heuristic_keywords, 
            'endpoint': heuristic_endpoint, 
            'ping': heuristic_ping }
        self.heuristic_results = dict() # key = result string; value = heuristic_result
        self.scoring_types = {
            'entropy': NormalScore("Entropy_Score", {'entropy':STANDARD_ENTROPY_SCORE}), 
            'password_validation': NormalScore("Password_Validation_Score", {'rating':STANDARD_PASSWORD_VALIDATION_SCORE}), 
            'imports': AdditiveScore("Import_Score", {'imports':STANDARD_IMPORTS_SCORE}),
            'keywords': NormalScore("Keyword_Score", {'keywords':STANDARD_KEYWORDS_SCORE}), 
            'endpoint': NormalScore("Endpoint_Score", {'endpoint':STANDARD_ENDPOINT_SCORE}), 
            'ping': NormalScore("Ping_Score", {'ping_check':STANDARD_PING_SCORE}) }
        
        self.max_possible_score = self.calculate_max_possible_score()

    def is_empty(self):
        if self.results:
            return False
        else:
            return True

    def json(self):
        return {self.name: self.results}

    def get_all_filepaths(self):
        filepath_set = set()
        for result in self.results['possible_secrets']:
            for filepath in result['filepaths']:
                filepath_set.add(filepath)
        
        return filepath_set

    def calculate_max_possible_score(self):
        max_possible_score = 0
        for scoring_type, object in self.scoring_types.items():
            if self.heuristics_status[scoring_type]:
                max_possible_score += object.max_score

        return max_possible_score
