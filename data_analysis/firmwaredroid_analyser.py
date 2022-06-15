from click import progressbar
from pymongo import MongoClient
from tqdm import tqdm

from data_analysis.firmwaredroid_data_merger import FirmwaredroidDataMerger

MAX_OUTPUT_LIMIT = 1000000
MAX_ELEMENTS = 100

EXCLUDED_PATTERNS = [
    "LinkFinder",
    "IP_Address",
    "Google_API_Key",
    "Generic_API_Key",
    "Firebase",
    "Google_Cloud_Platform_OAuth",
    "Generic_Secret",
    "Amazon_AWS_Access_Key_ID",
    "Password_in_URL",
    "PGP_private_key_block",
    "RSA_Private_Key"
]

class FirmwareDroidAnalyser():
    def __init__(self):
        self.client = MongoClient("mongodb://mongodbreader1:j8m88frSYjiKtdmZGP8BY6ZPdvQJyfpF@160.85.255.220:27017/?directConnection=true&authSource=FirmwareDroid")
        self.db = self.client["FirmwareDroid"]
        self._firmwaredroid_data_merger = FirmwaredroidDataMerger()
        # self.output = "data.txt"
        # self.fileout = open(self.output, "%s" % ("w"))

    def start_analysis(self):
        # self.analyse_apks()
        self.analyse_apk_leaks()

    def get_apk_names(self):
        apk_names = self.get_apks()

        apk_list = list()
        for apk_name in apk_names:
            if apk_name["filename"] not in apk_list:
                apk_list.append(apk_name["filename"])

        print(len(apk_list))
        
        return apk_list
    
    def get_apkleaks_information_with_appnames(self):
        # Step 0
        apkleaks_results_with_appnames = self.get_apk_leaks_reports_with_app_name()

        # Step 1a
        appnames_with_apkleaks_results_dict = self._firmwaredroid_data_merger.check_firmwaredroid_data_for_merges(apkleaks_results_with_appnames, MAX_OUTPUT_LIMIT)

        # Step 1b
        apkleaks_results_with_result_length = self.count_secret_amount(appnames_with_apkleaks_results_dict)

        # Organize results as dict
        firmwaredroid_apkleaks_data = dict()
        for entry in apkleaks_results_with_result_length:
            appname = entry["appname"]
            
            apkleaks_results_dict = dict()
            apkleaks_results_dict["secret_size"] = entry["secret_size"]
            apkleaks_results_dict["results"] = entry["results"]

            firmwaredroid_apkleaks_data[appname] = apkleaks_results_dict

        print(" --> Received all FirmewareDroid APKLeaks results")
        return firmwaredroid_apkleaks_data

    def get_top_most_apk_results(self):
        # Step 0
        apkleaks_results_with_appnames = self.get_apk_leaks_reports_with_app_name()

        # Step 1a
        appnames_with_apkleaks_results_dict = self._firmwaredroid_data_merger.check_firmwaredroid_data_for_merges(apkleaks_results_with_appnames, MAX_OUTPUT_LIMIT)

        # Step 1b
        apkleaks_results_with_result_length = self.count_secret_amount(appnames_with_apkleaks_results_dict)
        
        # Step 2
        print("--- Sort all apks according to their result size ---")
        apkleaks_results_with_result_length.sort(key=self.get_secret_size, reverse=True)

        # Step 3
        return self.organize_sorted_apkleaks_secrets(apkleaks_results_with_result_length)  

    def count_secret_amount(self, appnames_with_apkleaks_results_dict):
        print("--- Calculate secret amount for each result in FirmwareDroid DB ---")
        apkleaks_results_with_result_length = list()
        progressbar = tqdm(total=len(appnames_with_apkleaks_results_dict.keys()))
        for appname, apkleaks_results in appnames_with_apkleaks_results_dict.items():
                progressbar.set_description("Process %s" % appname)    

                apkleaks_results_dict = dict()

                apkleaks_results_dict["appname"] = appname
                apkleaks_results_dict["secret_size"] = 0
                apkleaks_results_dict["results"] = apkleaks_results

                for apkleaks_result in apkleaks_results:
                    if apkleaks_result["name"] != "LinkFinder" and apkleaks_result["name"] != "JSON_Web_Token" and apkleaks_result["name"] != "IP_Address":
                        apkleaks_results_dict["secret_size"] += len(apkleaks_result["matches"])
 
                apkleaks_results_with_result_length.append(apkleaks_results_dict)

                progressbar.update(1)
        
        return apkleaks_results_with_result_length

    def organize_sorted_apkleaks_secrets(self, apkleaks_results_with_result_length):
        print("--- Collect top most APKLeaks results from FirmwareDroid DB ---")
        firmwaredroid_apkleaks_data = dict()
        progressbar = tqdm(total=MAX_ELEMENTS)
        for apkleaks_result in apkleaks_results_with_result_length[0:MAX_ELEMENTS]:
            appname = apkleaks_result["appname"]

            progressbar.set_description("Process %s" % appname)    

            secrets = {'results':apkleaks_result["results"], 'secret_size': apkleaks_result["secret_size"] }
            firmwaredroid_apkleaks_data[appname] = secrets

            progressbar.update(1)
        
        print(f"  --> Collected secrets from {len(firmwaredroid_apkleaks_data.keys())}/{MAX_ELEMENTS} apks")
        return firmwaredroid_apkleaks_data
    
    def get_secret_size(self, elem):
        return elem["secret_size"]


    def analyse_apk_leaks(self):
        apkleaks_reports = self.get_apk_leaks_reports()

        count = 0
        for apkleaks_report in apkleaks_reports:
            for result in apkleaks_report["results"]["results"]:
                if self.exclude_patterns(result["name"]):
                    count += 1
                    stdout = str(count)+": "+apkleaks_report["results"]["package"] + "\n"
                    stdout += "  --> Android_app_id: "+str(apkleaks_report["android_app_id_reference"]) + "\n"
                    stdout += "  --> " + str(result) + "\n"
                    print(stdout)
                    self.fileout.write("%s" % (stdout))

            if count >= MAX_OUTPUT_LIMIT and MAX_OUTPUT_LIMIT != 0:
                break
    
    def exclude_patterns(self, pattern):
        for excluded_pattern in EXCLUDED_PATTERNS:
            if pattern == excluded_pattern:
                return False
        
        return True
    
    def get_apks(self):
        collection = self.db["android_app"]
        results = collection.find({}, { "_id": 0, "filename": 1})

        return results 

    def get_apk_leaks_reports(self):
        collection = self.db["apk_leaks_report"]
        results = collection.find({})

        return results 

    def get_apk_leaks_reports_with_app_name(self):
        collection = self.db["apk_leaks_report"]
        results = collection.aggregate([
                {
                    '$lookup':
                    {
                        'from': "android_app",
                        'localField': "android_app_id_reference",
                        'foreignField': "_id",
                        'as': "android_app"
                    } 
                }, 
                { 
                    '$limit': MAX_OUTPUT_LIMIT 
                }
                ])

        return results 
