import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additive_score_type import AdditiveScore

NAME = "Amazon_AWS_Access_Key_ID"
REGEXES = ["([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"]

KEYWORD_REGEXES = ["[<]?.*[a|A][m|M][a|A][z|Z][o|O][n|N].*[=|>].*", "[<]?.*[a|A][w|W][s|S].*[=|>].*", "[<]?.*[k|K][e|E][y|Y].*[=|>].*", 
                    "[<]?.*[a|A][c|C][c|C][e|E][s|S][s|S][_|-| ]?[k|K][e|E][y|Y].*[=|>].*"]

KEYWORD_SCORE = 10
BETTER_KEYWORD_SCORE = 20

class AwsAccessKeyIdPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_keywords=True)

        self.scoring_types['keywords'] = NormalScore("Keyword_Score", {
            KEYWORD_REGEXES[0]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[1]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[2]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[3]:BETTER_KEYWORD_SCORE })

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 