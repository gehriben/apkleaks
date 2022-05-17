class Pattern():
    def __init__(self, name, regexes, heuristic_entropy=False, heuristic_password=False, 
                heuristic_imports=False, heuristic_keywords=False, heuristic_endpoint=False, heuristic_ping=False):
        self.name = name
        self.regexes = regexes
        self.results = dict() # key = file path; value = found secret
        self.heuristic_results = dict() # key = result string; value = heuristic_result

        self.heuristic_entropy = heuristic_entropy
        self.heuristic_password = heuristic_password
        self.heuristic_imports = heuristic_imports
        self.heuristic_keywords = heuristic_keywords
        self.heuristic_endpoint = heuristic_endpoint
        self.heuristic_ping = heuristic_ping

