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
