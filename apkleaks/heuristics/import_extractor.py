import traceback
import re

IMPORT_REGEX = "[i|I][m|M][p|P][o|O][r|R][t|T] [a-zA-Z.]{1,}[;]"

class ImportExtractor():
    def __init__(self, filepaths, import_regexes):
        self.filepaths = filepaths
        self.import_regexes = import_regexes
    
    def do_import_extraction(self):
        extracted_imports = self.__extract_imports(self.filepaths)
        return self.__check_imports(self.import_regexes, extracted_imports)

    def __extract_imports(self, filepaths):
        extracted_imports = dict()
        for filepath in filepaths:
            with open(filepath, errors='ignore') as handle:
                try:
                    for line in handle.readlines():
                        matcher = re.compile(IMPORT_REGEX)
                        result = matcher.search(line)
                        if result:
                            if filepath not in extracted_imports:
                                extracted_imports[filepath] = list()
                            extracted_imports[filepath].append(line)
                except Exception:
                    print(traceback.format_exc())
        
        return extracted_imports

    def __check_imports(self, import_regexes, extracted_imports_dict):
        found_imports = dict()
        try:
            for filepath, extracted_imports in extracted_imports_dict.items():
                for extracted_import in extracted_imports:
                    for regex in import_regexes:
                        matcher = re.compile(regex)
                        result = matcher.search(extracted_import)
                        if result:
                            if filepath not in found_imports:
                                found_imports[filepath] = list()
                            found_imports[filepath].append(extracted_import)
        except Exception:
            print(traceback.format_exc())

        return found_imports