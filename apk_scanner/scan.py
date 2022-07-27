import argparse
import os
import json
from re import S
import shutil
import traceback
import configparser

from pymongo.errors import DocumentTooLarge

from apkleaks.apkleaks import APKLeaks
from apk_scanner.file_reader import File_Reader
from apk_scanner.api import API
from apk_scanner.db_manager import MongoDB
from data_analysis.data_analyser import DataAnalyser
from data_analysis.data_visualisation import DataVisualisation

MAX_ITERATIONS = 0

class Scan():
    def __init__(self):
        self._file_reader = File_Reader()
        self._api = API()
        self._db_manager = MongoDB()
        self.data_analyser = DataAnalyser()
        self.data_visualiser = DataVisualisation()
        self.config = configparser.ConfigParser()
        
        self.config.read('config.cfg')
        self.apk_path = '..' + self.config['AdvancedAPKLeaks']['mountpoint'] + self.config['AdvancedAPKLeaks']['apk_folder']
        self.results_path = '..' + self.config['AdvancedAPKLeaks']['mountpoint'] + self.config['AdvancedAPKLeaks']['results_folder']
        self.sources_path = '..' + self.config['AdvancedAPKLeaks']['mountpoint'] + self.config['AdvancedAPKLeaks']['source_folder']
        self.verbose = self.config['AdvancedAPKLeaks']['verbose']
        self.wipe_mode = self.config['AdvancedAPKLeaks']['wipe_resources']
        self.include_firmware_droid_data = self.config['AdvancedAPKLeaks']['include_firmware_droid_data']

    def initalization(self):
        if not os.path.exists(self.apk_path):
            os.mkdir(self.apk_path)
        if not os.path.exists(self.results_path):
            os.mkdir(self.results_path)
        if not os.path.exists(self.sources_path):
            os.mkdir(self.sources_path)

    def start_scan(self):
        if not os.path.exists(self.apk_path) or not os.path.exists(self.results_path) or not os.path.exists(self.sources_path):
            print("Error! You need to initialise the application first!")
            return

        # Get all apks and stores them
        if self.include_firmware_droid_data == 'true':
            print(f"Including FirmwareDroid Data activated. Collecting Secrets from FirmwareDroid DB!")
            self.data_analyser.start_firmwaredroid_analysis()
            self._api.get_all_apks()

        apk_file_list = self._file_reader.read_files(self.apk_path)
        print("Scanner found %s APKs. Start scanning!" % (len(apk_file_list)))
        count_files = 0
        """for filename in apk_file_list:
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
                except DocumentTooLarge:
                    print("DocumentTooLarge Exception! Heuristics will not be stored!")

                    reduced_output_json = dict()
                    reduced_output_json["appname"] = output_json["appname"]
                    reduced_output_json["packages"] = {'name': output_json["packages"]["name"], 'results': list() }
                    reduced_output_json["error_message"] = "DocumentTooLarge Exception: Results were too large so the heuristics are not displayed!"

                    for result in output_json["packages"]["results"]:
                        for key, value in result.items(): 
                            entry_dict = {key:dict()}
                            if 'possible_secrets' in value:
                                entry_dict[key]["possible_secrets"] = value["possible_secrets"]
                            if "valid_secrets" in value:
                               entry_dict[key]["valid_secrets"] = value["valid_secrets"] 
                            
                            reduced_output_json["packages"]["results"].append(entry_dict)
                    
                    self._db_manager.store_scan(reduced_output_json)
                except:
                    print("Error in apk scan! Skipping this apk!")
                    print(traceback.format_exc())
            else:
                print("App with name %s already in database. Skipping!" % (filename.replace('.apk', '')))"""
        
        print(" ==> Run data analysis")
        self.data_analyser.start_advanced_apkleask_analysis()
        print(" ==> Visualise data")
        self.data_visualiser.start_visualistaion()

    def path_builder(self, filename):
        apk_path = self.apk_path + '/' + filename
        apkname = filename.replace('.apk', '')
        result_path = self.results_path + '/' + apkname + '/' + apkname + '.txt'
        verbose_path = self.sources_path + '/' + apkname
        
        if os.path.exists(self.results_path + '/' + apkname) == False:
            os.mkdir(self.results_path + '/' + apkname)
        if os.path.exists(verbose_path) == False and self.verbose  == 'true':
            os.mkdir(verbose_path)
        elif os.path.exists(verbose_path) and self.wipe_mode  == 'true' and self.verbose == 'true':
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
        output = outputpath if self.verbose == 'true' else None
        pattern = None
        disargs = None
        verbose = verbosepath if self.verbose == 'true' else None
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