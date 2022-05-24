import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "Google_API_Key"
REGEXES = ["AIza[0-9A-Za-z\\-_]{35}"]

ENTROPY_THRESHOLD = 4.5
IMPORT_REGEXES = [".*[g|G][o|O][o|O][g|G][l|L][e|E].[m|M][a|A][p|P][s|S]*"]
KEYWORD_REGEXES = ["[<]?.*[a|A][p|P][i|I].*[=|>].*", "[<]?.*[g|G][o|O][o|O][g|G][l|L][e|E].*[=|>].*", "[<]?.*[k|K][e|E][y|Y].*[=|>].*"]

ENTROPY_SCORE = 10
IMPORT_SCORE = 5
KEYWORD_SCORE = 5

class GoogleApiPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.entropy_threshold = ENTROPY_THRESHOLD
        self.import_regexes = IMPORT_REGEXES
        self.keyword_regexes = KEYWORD_REGEXES

        self.entropy_score = ENTROPY_SCORE
        self.import_score = IMPORT_SCORE
        self.keyword_score = KEYWORD_SCORE

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True, heuristic_imports=True, heuristic_keywords=True)