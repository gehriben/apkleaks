from apkleaks.patterns.pattern import Pattern

NAME = "PGP_private_key_block"
REGEXES = ["-----BEGIN PGP PRIVATE KEY BLOCK-----"]


class PgpPrivateKeyBlockPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        Pattern.__init__(self, self.name, self.regexes)

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 