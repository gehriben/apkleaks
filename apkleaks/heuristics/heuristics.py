from heuristics.import_extractor import ImportExtractor
from heuristics.keyword_searcher import KeywordSearcher

class Heuristics():
    def __init__(self):
        self._import_extractor = ImportExtractor()
        self._keyword_searcher = KeywordSearcher()
    
    def applay_heuristics(self, pattern)