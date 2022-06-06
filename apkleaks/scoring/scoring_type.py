class ScoringType():
    def __init__(self, name, scores):
        self.name = name
        self.scores = scores
        self.max_score = self.calculate_max_score()
    
    def calculate_max_score(self):
        max_score = None
        for key, value in self.scores.items():
            if max_score is None or value < max_score:
                max_score = value
        
        return max_score

