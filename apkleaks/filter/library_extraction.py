import os
import re

from pipes import quote
from pathlib import Path

from apkleaks.colors import color as col

class LibraryExtraction():
    def __init__(self) -> None:
        self.objdump = "objdump"

    def start_decompiling(self, file):
        if file.endswith(".so"):
            return self.decompile_so_files(file)

        raise Exception("Not a valid file!")

    def decompile_so_files(self, file):
        outputfile = file+".txt"
        if not os.path.exists(outputfile):
            print("** Decompiling %s Library..." % (os.path.basename(file)))
            args = [self.objdump, "-s -j .rodata", quote(file), " | xxd -r -p > "+quote(outputfile)]

            try:
                args.extend(re.split(r"\s|=", self.disarg))
            except Exception:
                pass
            comm = "%s" % (" ".join(arg for arg in args))
            comm = comm.replace("\'","\"")
            os.system(comm)