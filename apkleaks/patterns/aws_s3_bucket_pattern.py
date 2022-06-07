import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additive_score_type import AdditiveScore

NAME = "Amazon_AWS_S3_Bucket"
REGEXES = [
		"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
		"//s3\\.amazonaws\\.com/[a-z0-9._-]+",
		"[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
		"[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
		"[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
		"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	]

KEYWORD_REGEXES = ["[<]?.*[a|A][m|M][a|A][z|Z][o|O][n|N].*[=|>].*", "[<]?.*[a|A][w|W][s|S].*[=|>].*", "[<]?.*[s|S][3].*[=|>].*", 
                    "[<]?.*[s|S][3][_|-| ]?[b|B][u|U][c|C][e|E][t|T].*[=|>].*"]

KEYWORD_SCORE = 10
BETTER_KEYWORD_SCORE = 20

class AwsS3BucketPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.keyword_regexes = KEYWORD_REGEXES

        Pattern.__init__(self, self.name, self.regexes, heuristic_keywords=True)

        self.scoring_types['keywords'] = NormalScore("Keyword_Score", {
            KEYWORD_REGEXES[0]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[1]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[2]:KEYWORD_SCORE, 
            KEYWORD_REGEXES[3]:BETTER_KEYWORD_SCORE })

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 