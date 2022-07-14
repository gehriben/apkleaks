from apkleaks.heuristics.entropy_calculator import EntropyCalculator
from apkleaks.heuristics.import_extractor import ImportExtractor
from apkleaks.heuristics.keyword_searcher import KeywordSearcher
from apkleaks.heuristics.password_validator import PasswordValidator
from apkleaks.heuristics.ping_check import PingCheck
from apkleaks.heuristics.word_filter import word_filter
from apkleaks.heuristics.endpoint_validation import EndpointValidation

class Heuristics():
    def __init__(self):
        self._password_validator = PasswordValidator()
        self._ping_check = PingCheck()
        self._word_filter = word_filter
        self._endpoint_validation = EndpointValidation()
    
    def apply_heuristics(self, pattern):
        for heuristic_name, heuristic_status in pattern.heuristics_status.items(): 
            if heuristic_status and 'possible_secrets' in pattern.results:
                if heuristic_name == 'entropy':
                    self.__do_entropy_calculation(pattern)
                elif heuristic_name == 'imports':
                    self.__do_import_extraction(pattern)
                elif heuristic_name == 'keywords':
                    self.__do_keyword_search(pattern)
                elif heuristic_name == 'password_validation':
                    self.__do_password_validation(pattern)
                elif heuristic_name == 'ping':
                    self.__do_ping_check(pattern)
                elif heuristic_name == 'word_filter':
                    self.__do_word_filter(pattern)
                elif heuristic_name == 'endpoint_validation':
                    self.__do_endpoint_validation(pattern)


    def __do_entropy_calculation(self, pattern):
        entropy_results = list()
        for result in pattern.results['possible_secrets']:
            entropy_calculator = EntropyCalculator()
            entropy = entropy_calculator.calculate_shannon_entropy(result['secret'])
            entropy_result_json = {
                'secret':result['secret'],
                'entropy':entropy
            }
            entropy_results.append(entropy_result_json)
        
        if entropy_results:
            pattern.results['entropy_calculator'] = entropy_results

    def __do_import_extraction(self, pattern):
        import_extractor = ImportExtractor(list(pattern.get_all_filepaths()), pattern.import_regexes)
        imports = import_extractor.do_import_extraction()

        import_results = list()
        for result in pattern.results['possible_secrets']:
            import_list= list()
            for filepath in result['filepaths']:
                if filepath in imports:    
                    import_list.extend(imports[filepath])

            if import_list:
                import_result_json = {
                    'secret':result['secret'],
                    'imports':import_list
                }
            else:
               import_result_json = {
                    'secret':result['secret'],
                    'imports':'No matching imports found!'
                } 

            import_results.append(import_result_json)
        
        if import_results:
            pattern.results['import_extractor'] = import_results

    def __do_keyword_search(self, pattern):
        keyword_searcher = KeywordSearcher(pattern.keyword_regexes)
        keywords = keyword_searcher.search_keywords(list(pattern.get_all_filepaths()))
        
        keyword_results = list()
        for result in pattern.results['possible_secrets']:
            keyword_dict= dict()
            for filepath in result['filepaths']:
                if filepath in keywords:
                    for regex, search_results in keywords[filepath].items():
                        if regex not in keyword_dict:
                            keyword_dict[regex] = list()
                        
                        keyword_dict[regex].extend(search_results)

            if keyword_dict:
                import_result_json = {
                    'secret':result['secret'],
                    'keywords':keyword_dict
                }
            else:
                import_result_json = {
                    'secret':result['secret'],
                    'keywords':'No matching keywords found!'
                } 

            keyword_results.append(import_result_json)

        if keyword_results:
            pattern.results['keyword_searcher'] = keyword_results

    def __do_password_validation(self, pattern):
        password_ratings = list()
        for result in pattern.results['possible_secrets']:
            password_rating = self._password_validator.validatePassword(result['secret'])
            if password_rating:
                password_rating_json = {
                    'secret':result['secret'],
                    'rating':password_rating
                }
            else:
                password_rating_json = {
                    'secret':result['secret'],
                    'rating':'it is a valid password'
                }
            
            password_ratings.append(password_rating_json)
        
        if password_ratings:
            pattern.results['password_validator'] = password_ratings

    def __do_ping_check(self, pattern):
        ping_checks = list()
        for result in pattern.results['possible_secrets']:
            if self._ping_check.check_ping(result['secret']):
                ping_check_json = {
                    'secret':result['secret'],
                    'ping_check':'Host is alive'
                }
            else:
                ping_check_json = {
                    'secret':result['secret'],
                    'ping_check':'Host is not reachable'
                }
            
            ping_checks.append(ping_check_json)

        if ping_checks:
            pattern.results['ping_check'] = ping_checks
    
    def __do_word_filter(self, pattern):
        word_filters = list()
        for result in pattern.results['possible_secrets']:
            words_in_secret = self._word_filter.filter_words(result['secret'])
            if not words_in_secret:
                word_filter_json = {
                    'secret':result['secret'],
                    'words':'Contains no english words'
                }
            else:
                word_filter_json = {
                    'secret':result['secret'],
                    'words': words_in_secret
                }
            
            word_filters.append(word_filter_json)

        if word_filters:
            pattern.results['word_filter'] = word_filters

    def __do_endpoint_validation(self, pattern):
        endpoint_validations = list()
        for result in pattern.results['possible_secrets']:
            endpoints = self._endpoint_validation.search_for_valid_endpoint(result['secret'])
            endpoint_validation_json = {
                'secret':result['secret'],
                'endpoints':endpoints
            }

            
            endpoint_validations.append(endpoint_validation_json)

        if endpoint_validations:
            pattern.results['endpoint_validation'] = endpoint_validations
