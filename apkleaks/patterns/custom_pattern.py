import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

class CustomPattern(Pattern):
    def __init__(self, name, regexes):
        self.name = name
        self.regexes = regexes

        Pattern.__init__(self, self.name, self.regexes)
        self.max_possible_score = Pattern.calculate_max_possible_score(self)