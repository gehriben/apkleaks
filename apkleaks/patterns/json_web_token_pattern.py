import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additive_score_type import AdditiveScore

NAME = "JSON_Web_Token"
REGEXES = ["^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$"] #(?i)^((?=.*[a-z])(?=.*[0-9])(?:[a-z0-9_=]+\\.){2}(?:[a-z0-9_\\-\\+\/=]*))$

ENTROPY_THRESHOLD = 4.5
KEYWORD_REGEXES = ["[<]?.*[j|J][w|W][t|T].*[=|>].*", "[<]?.*[t|T][o|O][k|K][e|E][n|N].*[=|>].*", 
                    "[<]?.*[j|J][s|S][o|O][n|N][_|-| ]?[w|W][e|E][b|B][_|-| ]?[t|T][o|O][k|K][e|E][n|N].*[=|>].*"]

KEYWORD_SCORE = 10
BETTER_KEYWORD_SCORE = 20

class JsonWebTokenPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.entropy_threshold = ENTROPY_THRESHOLD
        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True, heuristic_keywords=True)

        self.scoring_types['keywords'] = NormalScore("Keyword_Score", {
            KEYWORD_REGEXES[0]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[1]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[2]:BETTER_KEYWORD_SCORE })

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 