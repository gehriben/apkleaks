import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additional_score_type import AdditionalScore

NAME = "AWS_API_Key"
REGEXES = ["AKIA[0-9A-Z]{16}"]

KEYWORD_REGEXES = ["[<]?.*[a|A][m|M][a|A][z|Z][o|O][n|N].*[=|>].*", "[<]?.*[a|A][w|W][s|S].*[=|>].*", "[<]?.*[k|K][e|E][y|Y].*[=|>].*", "[<]?.*[a|A][p|P][i|I].*[=|>].*", 
                    "[<]?.*[a|A][w|W][s|S][_|-| ]?[a|A][p|P][i|I].*[=|>].*"]

KEYWORD_SCORE = 10
BETTER_KEYWORD_SCORE = 20

class AwsApiKeyPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_keywords=True)

        self.scoring_types['keywords'] = NormalScore("Keyword_Score", {
            KEYWORD_REGEXES[0]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[1]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[2]:KEYWORD_SCORE,
            KEYWORD_REGEXES[3]:KEYWORD_SCORE,  
            KEYWORD_REGEXES[4]:BETTER_KEYWORD_SCORE })

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 