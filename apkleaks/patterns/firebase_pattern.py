import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "Firebase"
REGEXES = ["[a-z0-9.-]+\\.firebaseio\\.com"]

KEYWORD_REGEXES = ["[<]?.*[f|F][i|I][r|R][e|E][b|B][a|A][s|S][e|E].*[=|>].*"]

class FirebasePattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_keywords=True)