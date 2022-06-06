import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "Key_Extractor"

ENTROPY_THRESHOLD = 4.8
IMPORT_REGEXES = ["[a-zA-Z]{1,}[.]{1,}crypto[.][a-zA-Z.;]{1,}"]
KEYWORD_REGEXES = ["[<]?.*[k|K][e|E][y|Y].*[=|>].*", "[<]?.*[s|S][e|E][c|C][r|R][e|E][t|T].*[=|>].*", "[<]?.*[a|A][e|E][s|S].*[=|>].*", ".*[d][o][F][i][n][a][l][(].*[)].*;"]

class KeyExtractorPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = None

        self.entropy_threshold = ENTROPY_THRESHOLD
        self.import_regexes = IMPORT_REGEXES
        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True, heuristic_imports=True, heuristic_keywords=True)