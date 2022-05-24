import os
import re
import traceback

class PatternMatcher():
    def __init__(self):
        pass
    
    def search_pattern_matches(self, pattern, sourcepath):
        matches = self.file_reader(pattern, sourcepath)
        for match in matches:
            if pattern.name == "LinkFinder":
                if re.match(r"^.(L[a-z]|application|audio|fonts|image|kotlin|layout|multipart|plain|text|video).*\/.+", match['secret']) is not None:
                    continue
                match['secret'] = match['secret'][len("'"):-len("'")]

        if matches:
            pattern.results['pattern_matcher'] = matches

    # Prüft ob ein Regex Pattern mit dem Source Code match und so ein Secret offenbart
    def file_reader(self, pattern, path) -> list():
        found_matches = []
        for fp, _, files in os.walk(path):
            for fn in files:
                filepath = os.path.join(fp, fn)
                with open(filepath, errors='ignore') as handle:
                    try:
                        linenumber = 0
                        for line in handle.readlines():
                            self.regex_matcher(found_matches, pattern, line, linenumber, filepath)
                            linenumber += 1
                    except Exception:
                        print(traceback.format_exc())

        return found_matches

    def regex_matcher(self, found_matches, pattern, line, linenumber, filepath) -> list():
        for regex in pattern.regexes:
            matcher = re.compile(regex)
            result = matcher.search(line)
            if result:
                self.oragnize_result(found_matches, result.group(), line, linenumber, filepath)
        
        return found_matches

    def oragnize_result(self, found_matches, found_secret, line, linenumber, filepath) -> list():
        for found_match in found_matches:
            if found_match['secret'] == found_secret:
                found_match['line_content'].append(line)
                found_match['linenumbers'].append(linenumber)
                found_match['filepaths'].append(filepath)
        
                return
        
        result = {
            'secret': found_secret,
            'line_content': [line,],
            'linenumbers': [linenumber,],
            'filepaths': [filepath,]
        }

        found_matches.append(result)

