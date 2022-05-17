import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

class CustomPattern(Pattern):
    def __init__(self, name, regexes, entropy):
        self.name = name
        self.regexes = regexes
        self.entropy = entropy
        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True)