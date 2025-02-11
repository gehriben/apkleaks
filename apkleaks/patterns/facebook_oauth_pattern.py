import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "Facebook_OAuth"
REGEXES = ["[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]"]

ENTROPY_THRESHOLD = 4.5
IMPORT_REGEXES = [".*[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*"]
KEYWORD_REGEXES = ["[<]?.*[o|O][a|A][u|U][t|T][h|H].*[=|>].*", "[<]?.*[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[=|>].*"]

class FacebookOauthPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.entropy_threshold = ENTROPY_THRESHOLD
        self.import_regexes = IMPORT_REGEXES
        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True, heuristic_imports=True, heuristic_keywords=True)