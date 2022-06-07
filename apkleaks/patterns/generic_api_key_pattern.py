import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore

NAME = "Generic_API_Key"
REGEXES = ["[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]"]

ENTROPY_THRESHOLD = 4.5
IMPORT_REGEXES = [".*[n|N][e|E][t|T].[u|U][r|R][l|L].*", ".*[h|H][t|T][t|T][p|P][s|S][u|U][r|R][l|L][c|C][o|O][n|N][n|N][e|E][c|C][t|T][i|I][o|O][n|N].*"]
KEYWORD_REGEXES = ["[<]?.*[a|A][p|P][i|I].*[=|>].*", "[<]?.*[k|K][e|E][y|Y].*[=|>].*", 
                    "[<]?.*[a|A][p|P][i|I][_|-| ]?[k|K][e|E][y|Y].*[=|>].*"]

KEYWORD_SCORE = 10
BETTER_KEYWORD_SCORE = 20

class GenericApiKeyPattern(Pattern):
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
            KEYWORD_REGEXES[2]:BETTER_KEYWORD_SCORE })

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 