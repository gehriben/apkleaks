import os

from pathlib import Path

from apkleaks.patterns.pattern import Pattern
from apkleaks.scoring.normal_score_type import NormalScore
from apkleaks.scoring.additional_score_type import AdditionalScore

NAME = "Amazon_AWS_S3_Bucket"
REGEXES = [
		"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
		"//s3\\.amazonaws\\.com/[a-z0-9._-]+",
		"[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
		"[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
		"[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
		"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	]

ENTROPY_THRESHOLD = 3.0

class AwsS3BucketPattern(Pattern):
    def __init__(self):
        self.name = NAME
        self.regexes = REGEXES

        self.entropy_threshold = ENTROPY_THRESHOLD

        Pattern.__init__(self, self.name, self.regexes, heuristic_entropy=True)

        self.max_possible_score = Pattern.calculate_max_possible_score(self) 