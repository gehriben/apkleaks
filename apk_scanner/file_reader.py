import os


class File_Reader():
    def __init__(self):
        pass

    def read_files(self, apk_dir):
        return os.listdir(apk_dir)
