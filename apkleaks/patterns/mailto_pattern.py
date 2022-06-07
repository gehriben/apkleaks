import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "Mailto"
REGEXES = ["(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+"]

KEYWORD_REGEXES = ["[<]?.*[m|M][a|A][i|I][l|L].*[=|>].*", "[<]?.*[a|A][d|D][d|D][r|R][e|E][s|S][s|S].*[=|>].*"]

class MailtoPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_keywords=True)