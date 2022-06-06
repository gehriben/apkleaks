import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additive_score_type import AdditiveScore

NAME = "Google_API_Key"
REGEXES = ["AIza[0-9A-Za-z\\-_]{35}"]

ENTROPY_THRESHOLD = 4.7
IMPORT_REGEXES = [".*[g|G][o|O][o|O][g|G][l|L][e|E].[m|M][a|A][p|P][s|S]*"]
KEYWORD_REGEXES = ["[<]?.*[a|A][p|P][i|I].*[=|>].*", "[<]?.*[g|G][o|O][o|O][g|G][l|L][e|E].*[=|>].*", "[<]?.*[k|K][e|E][y|Y].*[=|>].*", 
                    "[<]?.*[g|G][o|O][o|O][g|G][l|L][e|E][_|-| ]?[a|A][p|P][i|I].*[=|>].*"]

KEYWORD_SCORE = 10
BETTER_KEYWORD_SCORE = 20

class GoogleApiPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.entropy_threshold = ENTROPY_THRESHOLD
        self.import_regexes = IMPORT_REGEXES
        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True, heuristic_imports=True, heuristic_keywords=True)

        self.scoring_types['keywords'] = NormalScore("Keyword_Score", {
            KEYWORD_REGEXES[0]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[1]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[2]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[3]:BETTER_KEYWORD_SCORE })

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 