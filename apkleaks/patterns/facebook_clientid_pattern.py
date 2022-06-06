import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additive_score_type import AdditiveScore

NAME = "Facebook_ClientID"
REGEXES = ["[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K](.{0,20})?['\"][0-9]{13,17}"]

ENTROPY_THRESHOLD = 4.5
IMPORT_REGEXES = [".*[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*"]
KEYWORD_REGEXES = ["[<]?.*[i|I][d|D].*[=|>].*", "[<]?.*[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[=|>].*"]

class FacebookClientidPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.entropy_threshold = ENTROPY_THRESHOLD
        self.import_regexes = IMPORT_REGEXES
        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True, heuristic_imports=True, heuristic_keywords=True)