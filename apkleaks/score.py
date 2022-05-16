from enum import Enum
from operator import truediv


class Scoremargin(Enum):
    AES = 40
    CREDENTIALS = 40


class Score():
    def __init__(self, type, value):
        self.type = type
        self.value = value
        self.score = 0

    def increase_score(self, amount):
        self.score += amount

    def reduce_score(self, amount):
        self.score -= amount

    def get_score(self):
        return self.score

    def get_value(self):
        return self.value

    def is_margin_reached(self):
        if self.score >= self.type.value:
            return True
        else:
            return False
