import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additional_score_type import AdditionalScore

NAME = "Credential_Extractor"

ENTROPY_THRESHOLD = 3.0

ENTROPY_SCORE = 5

class CredentialExtractorPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = None

        self.entropy_threshold = ENTROPY_THRESHOLD

        self.entropy_score = ENTROPY_SCORE

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True, heuristic_password=True, heuristic_word_filter=True)

        self.scoring_types['entropy'] = NormalScore("Entropy_Score", {'entropy':ENTROPY_SCORE})

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 