import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "IP_Address"
REGEXES = ["^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"]

KEYWORD_REGEXES = ["[<]?.*[i|I][p|P][ |_]?[a|A][d|D][d|D][r|R][e|E][s|S][s|S].*[=|>].*", "[<]?.*[h|H][o|O][s|S][t|T].*[=|>].*"]


class IpAddressPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_keywords=True, heuristic_ping=True)