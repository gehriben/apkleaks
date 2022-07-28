import os
import shutil

from apkleaks.utils import util
from apkleaks.colors import color as col
from apkleaks.filter.library_extraction import LibraryExtraction

ALLOWED_FILE_EXTENSIONS = [
	'.java',
	'.xml',
    '.dex',
    '.txt'
]

SPECIAL_FILE_EXTENSIONS = [
	'.so'
]

EXCLUDED_FILES = []

EXCLUDED_DIRECTORIES = [
    'android',
    'androidx',
    'google',
    'mysql',
    'kotlin',
    'kotlinx'
]

class FileFiltering():
    def __init__(self, sourcepath):
        self.sourcepath = sourcepath

    def filter_files(self):
        util.writeln("** Filtering files...", col.OKBLUE)

        folder_deletion_count = 0
        file_deletion_count = 0
        remaining_files = 0

        for fp, _, files in os.walk(self.sourcepath):
            if not self.check_folder(fp):
                shutil.rmtree(fp)
                folder_deletion_count += 1
            else:
                for fn in files:
                    filepath = os.path.join(fp, fn)
                    if not self.check_file(filepath):
                        os.remove(filepath)
                        file_deletion_count += 1
                        # print(f"  --> Removes {fn}!")
                    else:
                        remaining_files += 1
        
        print(f"Removed {folder_deletion_count} folders and {file_deletion_count} files!")
        print(f"{remaining_files} remaining files!")

        return remaining_files

    def check_file(self, filepath):
        if self.is_file_excluded(filepath):
            return False

        if self.is_file_special(filepath):
            library_extraction = LibraryExtraction()
            library_extraction.start_decompiling(filepath)

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

    def is_file_special(self, filepath):
        for special_file_extension in SPECIAL_FILE_EXTENSIONS:
            if filepath.endswith(special_file_extension):
                return True
        
        return False

    def check_folder(self, folderpath):
        if self.is_directory_excluded(folderpath):
            return False

        return True

    def is_directory_excluded(self, folderpath):
        for excluded_directory in EXCLUDED_DIRECTORIES:
            if folderpath.endswith('sources/'+excluded_directory):
                return True
        
        return False