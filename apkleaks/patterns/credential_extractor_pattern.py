import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern

NAME = "Credential_Extractor"

ENTROPY_THRESHOLD = 3.0

ENTROPY_SCORE = 10

class CredentialExtractorPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = None

        self.entropy_threshold = ENTROPY_THRESHOLD

        self.entropy_score = ENTROPY_SCORE

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True)