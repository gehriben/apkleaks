import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "Facebook_Access_Token"
REGEXES = ["EAACEdEose0cBA[0-9A-Za-z]+"]

ENTROPY_THRESHOLD = 4.5
IMPORT_REGEXES = [".*[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*"]
KEYWORD_REGEXES = ["[<]?.*[t|T][o|O][k|K][e|E][n|N].*[=|>].*", "[<]?.*[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[=|>].*"]

ENTROPY_SCORE = 10
IMPORT_SCORE = 5
KEYWORD_SCORE = 5

class FacebookAccessTokenPattern(Pattern):
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