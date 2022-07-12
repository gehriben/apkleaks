import argparse
import os
import json
import shutil

from apkleaks.apkleaks import APKLeaks
from apk_scanner.file_reader import File_Reader
from apk_scanner.api import API
from apk_scanner.db_manager import MongoDB

APK_PATH = '../apks/apk_files'
APKLEAKS_RESULTS_PATH = '../apks/results'
APKLEAKS_VERBOSE_PATH = '../apks/sources'

MAX_ITERATIONS = 0
VERBOSE = True
WIPE_SOURCES = False

class Scan():
    def __init__(self):
        self._file_reader = File_Reader()
        self._api = API()
        self._db_manager = MongoDB()

    def start_scan(self):
        # Get all apks and stores them
        # self._api.get_all_apks()

        apk_file_list = self._file_reader.read_files(APK_PATH)
        print("Scanner found %s APKs. Start scanning!" % (len(apk_file_list)))
        count_files = 0
        for filename in apk_file_list:
            if not self._db_manager.get_scan_by_appname(filename.replace('.apk', '')):
                try:
                    print("*** SCANNING "+filename+" ***")
                    apk_path, result_path, verbose_path = self.path_builder(filename)
                    apkleaks = self.init_apkleaks(apk_path, result_path, verbose_path)
                    result_json = self.run_apkleaks(apkleaks)
                    output_json = self.parse_output_json(filename, result_json)
                    self._db_manager.store_scan(output_json)
                    print("  ---> Results saved in MongoDB!")

                    count_files += 1
                    if count_files >= MAX_ITERATIONS and MAX_ITERATIONS != 0:
                        break
                except:
                    print("Error in apk scan! Skipping this apk!")
            else:
                print("App with name %s already in database. Skipping!" % (filename.replace('.apk', '')))

    def path_builder(self, filename):
        apk_path = APK_PATH + '/' + filename
        apkname = filename.replace('.apk', '')
        result_path = APKLEAKS_RESULTS_PATH + '/' + apkname + '/' + apkname + '.txt'
        verbose_path = APKLEAKS_VERBOSE_PATH + '/' + apkname
        
        if os.path.exists(APKLEAKS_RESULTS_PATH + '/' + apkname) == False:
            os.mkdir(APKLEAKS_RESULTS_PATH + '/' + apkname)
        if os.path.exists(verbose_path) == False and VERBOSE == True:
            os.mkdir(verbose_path)
        elif os.path.exists(verbose_path) and WIPE_SOURCES and VERBOSE:
            print(f"Source folder for {apkname} already exists! Wipe mode is activated so folder will be deleted an recreated.")
            shutil.rmtree(verbose_path)
            os.mkdir(verbose_path)

        return apk_path, result_path, verbose_path

    def init_apkleaks(self, apk_path, result_path, verbose_path):
        file, output, pattern, disargs, verbose, json, pattern_matcher, key_extractor, credentials_extractor = self.build_arguments(apk_path, result_path, verbose_path)
        apkleaks = APKLeaks(None, file=file, verbose=verbose, json=json, disarg=disargs, output=output, pattern=pattern, 
        pattern_matcher=pattern_matcher, key_extractor=key_extractor, credentials_extractor=credentials_extractor)

        return apkleaks
    
    def build_arguments(self, filepath, outputpath, verbosepath):
        file = filepath
        output = outputpath if VERBOSE else None
        pattern = None
        disargs = None
        verbose = verbosepath if VERBOSE else None
        json = False
        pattern_matcher = True
        key_extractor = True
        credentials_extractor = True
        return file, output, pattern, disargs, verbose, json, pattern_matcher, key_extractor, credentials_extractor

    def run_apkleaks(self, apkleaks):
        results_json = ''
        
        try:
            apkleaks.initialization()
            apkleaks.scanning()

            results_json = apkleaks.out_json
        finally:
            apkleaks.cleanup()

        return results_json

    def parse_output_json(self, filename, raw_output_json):
        output_json = dict()
        output_json['appname'] =  filename.replace('.apk', '')
        output_json['packages'] = {'name':raw_output_json['package'], 'results':raw_output_json['results']}
        return output_json