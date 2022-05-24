import math

class EntropyCalculator():
    def __init__(self, string_sequence):
        self.string_sequence = string_sequence

    def calculate_shannon_entropy(self):
        """
        Calculates the Shannonx entropy for the given string.

        :param string: String to parse.
        :type string: str

        :returns: Shannon entropy (min bits per byte-character).
        :rtype: float
        """
        ent = 0.0
        if len(self.string_sequence) < 2:
            return ent
        size = float(len(self.string_sequence))
        freq = dict()
        for char in self.string_sequence:
            if char in freq:
                freq[char] = freq[char] + 1
            else:
                freq[char] = 1

        for value in freq.values():		
            if value > 0:
                prop = float(value) / size
                ent = ent + prop * math.log(1/prop, 2)
        return ent