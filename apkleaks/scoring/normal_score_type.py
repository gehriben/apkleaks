from apkleaks.scoring.scoring_type import ScoringType

class NormalScore(ScoringType):
    def __init__(self, name, scores):
        ScoringType.__init__(self, name, scores)