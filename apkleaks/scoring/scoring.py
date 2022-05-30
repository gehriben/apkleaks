class Scoring():
    def __init__(self):
        self.total_possible_score = 0

    def do_scoring(self, pattern):
        for heuristic_name, heuristic_status in pattern.heuristics_status.items():
            if heuristic_status:
                if heuristic_name == 'entropy' and 'entropy_calculator' in pattern.results:
                    self.__score_entropy(pattern)
                elif heuristic_name == 'imports' and 'import_extractor' in pattern.results:
                    self.__score_imports(pattern)
                elif heuristic_name == 'keywords' and 'keyword_searcher' in pattern.results:
                    self.__score_keyword_search(pattern)
        
        if not pattern.is_empty():
            self.__calculate_total_score(pattern)

    def __score_entropy(self, pattern):
        self.total_possible_score += pattern.entropy_score
        for entropy_result in pattern.results['entropy_calculator']:
            score = 0
            if entropy_result['entropy'] > pattern.entropy_threshold:
                score = pattern.entropy_score
                entropy_result['score'] = score

    def __score_imports(self, pattern):
        self.total_possible_score += pattern.import_score
        for import_result in pattern.results['import_extractor']:
            score = 0
            if import_result['imports'] != 'No matching imports found!':
                score = pattern.import_score
                
            import_result['score'] = score

    def __score_keyword_search(self, pattern):
        self.total_possible_score += pattern.keyword_score
        for keyword_searcher in pattern.results['keyword_searcher']:
            score = 0
            if keyword_searcher['keywords'] != 'No matching keywords found!':
                score = pattern.keyword_score
                
            keyword_searcher['score'] = score

    def __calculate_total_score(self, pattern):
        for secret in pattern.results['possible_secrets']:
            total_score = 0
            for heuristic_name, heuristic_content in pattern.results.items():
                for result in heuristic_content:
                    if secret['secret'] == result['secret'] and 'score' in result:
                        total_score += result['score']
        
            secret['total_score'] = f"{total_score}/{self.total_possible_score}"
