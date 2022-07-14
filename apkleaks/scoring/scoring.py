from operator import pos


class Scoring():
    def __init__(self):
        pass

    def do_scoring(self, pattern):
        for heuristic_name, heuristic_status in pattern.heuristics_status.items():
            if heuristic_status:
                if heuristic_name == 'entropy' and 'entropy_calculator' in pattern.results:
                    self.__score_entropy(pattern)
                elif heuristic_name == 'imports' and 'import_extractor' in pattern.results:
                    self.__score_imports(pattern)
                elif heuristic_name == 'keywords' and 'keyword_searcher' in pattern.results:
                    self.__score_keyword_search(pattern)
                elif heuristic_name == 'password_validation' and 'password_validator' in pattern.results:
                    self.__score_password_validation(pattern)
                elif heuristic_name == 'ping' and 'ping_check' in pattern.results:
                    self.__score_ping_check(pattern)
                elif heuristic_name == 'word_filter' and 'word_filter' in pattern.results:
                    self.__score_word_filter(pattern)
                elif heuristic_name == 'endpoint_validation' and 'endpoint_validation' in pattern.results:
                    self.__score_endpoint_validation(pattern)
        
        if not pattern.is_empty():
            self.__calculate_total_score(pattern)

    def __score_entropy(self, pattern):
        for entropy_result in pattern.results['entropy_calculator']:
            score = 0
            if entropy_result['entropy'] > pattern.entropy_threshold:
                score = pattern.scoring_types['entropy'].scores['entropy']
                entropy_result['score'] = score

    def __score_imports(self, pattern):
        for import_result in pattern.results['import_extractor']:
            score = 0
            if import_result['imports'] != 'No matching imports found!':
                score = pattern.scoring_types['imports'].scores['imports']
                
            import_result['score'] = score

    def __score_keyword_search(self, pattern):
        for keyword_searcher in pattern.results['keyword_searcher']:
            score = 0
            if keyword_searcher['keywords'] != 'No matching keywords found!':
                if 'keywords' in pattern.scoring_types['keywords'].scores:
                    score = pattern.scoring_types['keywords'].scores['keywords']
                else:
                    possible_score = 0
                    for regex, content in keyword_searcher['keywords'].items():
                        if content:
                            if pattern.scoring_types['keywords'].scores[regex] > possible_score:
                                possible_score = pattern.scoring_types['keywords'].scores[regex]
                        
                    score = possible_score
                
            keyword_searcher['score'] = score

    def __score_password_validation(self, pattern):
        for password_validation in pattern.results['password_validator']:
            score = 0
            if password_validation['rating'] == 'it is a valid password':
                score = pattern.scoring_types['password_validation'].scores['rating']
                
            password_validation['score'] = score

    def __score_ping_check(self, pattern):
        for ping_check in pattern.results['ping_check']:
            score = 0
            if ping_check['ping_check'] == 'Host is alive':
                score = pattern.scoring_types['ping'].scores['ping_check']
                
            ping_check['score'] = score

    def __score_word_filter(self, pattern):
        for word_filter in pattern.results['word_filter']:
            score = 0
            if word_filter['words'] == 'Contains no english words':
                score = pattern.scoring_types['word_filter'].scores['word_filter']
                
            word_filter['score'] = score
    
    def __score_endpoint_validation(self, pattern):
        for endpoint_validation in pattern.results['endpoint_validation']:
            score = 0
            if endpoint_validation['endpoints'] != 'No valid api endpoint found!':
                score = pattern.scoring_types['endpoint_validation'].scores['endpoint_validation']
                
            endpoint_validation['score'] = score

    def __calculate_total_score(self, pattern):
        for secret in pattern.results['possible_secrets']:
            total_score = 0
            for heuristic_name, heuristic_content in pattern.results.items():
                for result in heuristic_content:
                    if secret['secret'] == result['secret'] and 'score' in result:
                        total_score += result['score']
        
            secret['total_score'] = f"{total_score}/{pattern.max_possible_score}"
