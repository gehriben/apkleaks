from apkleaks.scoring.scoring_type import ScoringType

class AdditiveScore(ScoringType):
    def __init__(self, name, scores):
        ScoringType.__init__(self, name, scores)

        self.max_score = 0