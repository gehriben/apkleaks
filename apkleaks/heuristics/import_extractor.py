import traceback
import re

CRYPTO_IMPORTS = "import [a-zA-Z]{1,}[.]{1,}crypto[.][a-zA-Z.;]{1,}"

class ImportExtractor():
    def __init__(self):
        pass

    def check_crypto_imports(self, filepath):
        with open(filepath, errors='ignore') as handle:
            try:
                for line in handle.readlines():
                    matcher = re.compile(CRYPTO_IMPORTS)
                    mo = matcher.search(line)
                    if mo:
                        return True
            except Exception:
                print(traceback.format_exc())

        return False