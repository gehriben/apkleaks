import os
import re
import traceback

class PatternMatcher():
    def __init__(self):
        pass

    # Prüft ob ein Regex Pattern mit dem Source Code match und so ein Secret offenbart
    def file_reader(self, pattern, path) -> list():
        found_matches = []
        for fp, _, files in os.walk(path):
            for fn in files:
                filepath = os.path.join(fp, fn)
                with open(filepath, errors='ignore') as handle:
                    try:
                        for line in handle.readlines():
                            found_matches.extend(self.regex_matcher(pattern, line))
                    except Exception:
                        print(traceback.format_exc())

        return sorted(list(set(found_matches)))

    def regex_matcher(self, pattern, line) -> list():
        found_matches = list() 
        for regex in pattern.regexes:
            matcher = re.compile(regex)
            result = matcher.search(line)
            if result:
                found_matches.append(result.group())
        
        return found_matches