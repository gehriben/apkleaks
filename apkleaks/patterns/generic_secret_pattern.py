import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore

NAME = "Generic_Secret"
REGEXES = ["['|\"][0-9a-zA-Z!@#$%^&*-]{32,45}['|\"]"]
# REGEXES = ["[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]"]

ENTROPY_THRESHOLD = 3.5
IMPORT_REGEXES = [".*[c|C][r|R][y|Y][p|P][t|T][o|O].*", ".*[s|S][s|S][l|L].*"]
KEYWORD_REGEXES = ["[<]?.*[k|K][e|E][y|Y].*[\"|=|>].*", "[<]?.*[s|S][e|E][c|C][r|R][e|E][t|T].*[\"|=|>].*", 
"[<]?.*[u|U][u|U][i|I][d|D].*[\"|=|>].*", "[<]?.*[s|S][e|E][c|C][r|R][e|E][t|T][_|-| ]?[k|K][e|E][y|Y].*[\"|=|>].*"]

KEYWORD_SCORE = 10
BETTER_KEYWORD_SCORE = 20
WORD_FILTER_SCORE = 30

class GenericSecretPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.entropy_threshold = ENTROPY_THRESHOLD
        self.import_regexes = IMPORT_REGEXES
        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True, heuristic_imports=True, heuristic_keywords=True, heuristic_word_filter=True)

        self.scoring_types['keywords'] = NormalScore("Keyword_Score", {
            KEYWORD_REGEXES[0]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[1]:KEYWORD_SCORE,
            KEYWORD_REGEXES[2]:KEYWORD_SCORE,
            KEYWORD_REGEXES[3]:BETTER_KEYWORD_SCORE })

        self.scoring_types['word_filter'] = NormalScore("Word_Filter", {'word_filter':WORD_FILTER_SCORE})

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 