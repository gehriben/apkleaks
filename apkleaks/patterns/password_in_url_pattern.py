from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additive_score_type import AdditiveScore

NAME = "Password_in_URL"
REGEXES = ["[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"]

ENTROPY_THRESHOLD = 3.5


class PasswordInUrlPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.entropy_threshold = ENTROPY_THRESHOLD

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True)

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 