import os

from apkleaks.utils import util
from apkleaks.colors import color as col

ALLOWED_FILE_EXTENSIONS = [
	'.java',
	'.xml'
]

SPECIAL_FILE_EXTENSIONS = [
	'.so'
]

EXCLUDED_FILES = [
	'AndroidManifest.xml'
]

class FileFiltering():
    def __init__(self, sourcepath):
        self.sourcepath = sourcepath

    def filter_files(self):
        util.writeln("** Filtering files...", col.OKBLUE)
        deletion_count = 0
        for fp, _, files in os.walk(self.sourcepath):
            for fn in files:
                filepath = os.path.join(fp, fn)
                if not self.check_file(filepath):
                    os.remove(filepath)
                    deletion_count += 1
                    # print(f"  --> Removes {fn}!")
        
        print(f"Removed {deletion_count} files!")

    def check_file(self, filepath):
        if self.is_file_excluded(filepath):
            return False

        if not self.is_file_extension_allowed(filepath):
            return False

        return True

    def is_file_excluded(self, filepath):
        for excluded_file in EXCLUDED_FILES:
            if excluded_file in filepath:
                return True
        
        return False

    def is_file_extension_allowed(self, filepath):
        for allowed_file_extension in ALLOWED_FILE_EXTENSIONS:
            if filepath.endswith(allowed_file_extension):
                return True

        return False