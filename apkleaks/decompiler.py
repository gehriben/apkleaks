import io
import os
import re
import sys

from pipes import quote
from distutils.spawn import find_executable
from pathlib import Path
from contextlib import closing
from urllib.request import urlopen
from zipfile import ZipFile
from pyaxmlparser import APK

from apkleaks.colors import color as col
from apkleaks.utils import util

JADX_LIBRARY = "https://github.com/skylot/jadx/releases/download/v1.2.0/jadx-1.2.0.zip"

class Decompiler():
    def __init__(self, file, outputdir):
        self.apk = None
        self.file = file
        self.outputdir = outputdir
        self.main_dir = os.path.dirname(os.path.realpath(__file__))
        self.jadx = self.jadx = find_executable("jadx") if find_executable("jadx") is not None else os.path.join(str(Path(self.main_dir).parent), "jadx", "bin", "jadx%s" % (".bat" if os.name == "nt" else "")).replace("\\","/")
    
    def decompile(self):
        self.__integrity()
        self.__decompile_apk()

    def __apk_info(self):
        return APK(self.file)
    
    def __integrity(self):
        if os.path.exists(self.jadx) is False:
            util.writeln("Can't find jadx binary.", col.WARNING)
            valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
            while True:
                util.write("Do you want to download jadx? (Y/n) ", col.OKBLUE)
                try:
                    choice = input().lower()
                    if choice == "":
                        choice = valid["y"]
                        break
                    elif choice in valid:
                        choice = valid[choice]
                        break
                    else:
                        util.writeln("\nPlease respond with 'yes' or 'no' (or 'y' or 'n').", col.WARNING)
                except KeyboardInterrupt:
                    sys.exit(util.writeln("\n** Interrupted. Aborting.", col.FAIL))
            if choice:
                util.writeln("\n** Downloading jadx...\n", col.OKBLUE)
                self.__dependencies()
            else:
                sys.exit(util.writeln("\n** Aborted.", col.FAIL))
        if os.path.isfile(self.file):
            try:
                self.apk = self.__apk_info()
            except Exception as error:
                util.writeln(str(error), col.WARNING)
                sys.exit()
            else:
                return self.apk
        else:
            sys.exit(util.writeln("It's not a valid file!", col.WARNING))
    
    def __dependencies(self):
        try:
            with closing(urlopen(JADX_LIBRARY)) as jadx:
                with ZipFile(io.BytesIO(jadx.read())) as zfile:
                    zfile.extractall(os.path.join(str(Path(self.main_dir).parent), "jadx"))
            os.chmod(self.jadx, 33268)
        except Exception as error:
            util.writeln(str(error), col.WARNING)
            sys.exit()

    def __decompile_apk(self):
        # Dekompiliert die apk mit jadx und speichert das File im outputdir Ordner
        if not os.listdir(self.outputdir):
            util.writeln("** Decompiling APK...", col.OKBLUE)
            args = [self.jadx, self.file, "-d", self.outputdir]

            try:
                args.extend(re.split(r"\s|=", self.disarg))
            except Exception:
                pass
            comm = "%s" % (" ".join(quote(arg) for arg in args))
            comm = comm.replace("\'","\"")
            # comm = jadx [APK Name].apk -d outputdir
            os.system(comm)
        else:
            util.writeln("** Source file folder already exists. Skipping decompilation...", col.WARNING)
