import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "IP_Address"
REGEXES = ["(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"]

KEYWORD_REGEXES = ["[<]?.*[i|I][p|P][ |_]?[a|A][d|D][d|D][r|R][e|E][s|S][s|S].*[\"|=|>].*", "[<]?.*[h|H][o|O][s|S][t|T].*[\"|=|>].*", "[<]?.*[i|I][n|N][e|E][t|T].*[\"|=|>].*"]


class IpAddressPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_keywords=True, heuristic_ping=True, heuristic_word_filter=True)