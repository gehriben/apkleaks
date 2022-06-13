from click import progressbar
from pymongo import MongoClient
from tqdm import tqdm

MAX_OUTPUT_LIMIT = 1000000
MAX_ELEMENTS = 1000

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

        firmwaredroid_apkleaks_data = dict()

        apkleaks_informations_with_appnames = self.get_apk_leaks_reports_with_app_name()

        progressbar = tqdm(total=MAX_OUTPUT_LIMIT)
        print("--- Collect APKLeaks results from FirmwareDroid DB ---")
        for apkleaks_information_with_appnames in apkleaks_informations_with_appnames:
            if apkleaks_information_with_appnames["android_app"]:
                appname = apkleaks_information_with_appnames["android_app"][0]["filename"]

                progressbar.set_description("Process %s" % appname)    

                apkleaks_results = apkleaks_information_with_appnames["results"]["results"]
                firmwaredroid_apkleaks_data[appname] = apkleaks_results

                progressbar.update(1)

        print(" --> Received all FirmewareDroid APKLeaks results")
        return firmwaredroid_apkleaks_data

    def get_top_most_apk_results(self):
        # Step 0
        apkleaks_results_with_appnames = self.get_apk_leaks_reports_with_app_name()

        # Step 1a
        print("--- Merge apkleaks results with same appname together ---")
        appnames_with_apkleaks_results_dict = dict()
        progressbar = tqdm(total=MAX_OUTPUT_LIMIT)
        for entry in apkleaks_results_with_appnames:
            if entry["android_app"]:
                apkname = entry['android_app'][0]['filename']
                apkleaks_results = entry['results']['results']

                if apkname in appnames_with_apkleaks_results_dict:
                    progressbar.set_description("Merging %s" % apkname)

                    merged_results = self.merge_apkleaks_results(appnames_with_apkleaks_results_dict, apkname, apkleaks_results)
                    appnames_with_apkleaks_results_dict[apkname] = merged_results
                else:
                    progressbar.set_description("Adding %s" % apkname)
                    
                    appnames_with_apkleaks_results_dict[apkname] = apkleaks_results

            progressbar.update(1)
        

        # Step 1b
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
        
        # Step 2
        print("--- Sort all apks according to their result size ---")
        apkleaks_results_with_result_length.sort(key=self.get_secret_size, reverse=True)

        # Step 3
        return self.organize_sorted_apkleaks_secrets(apkleaks_results_with_result_length)

    def merge_apkleaks_results(self, appnames_with_apkleaks_results_dict, apkname, apkleaks_results):
        merged_results_list = list()

        old_results = appnames_with_apkleaks_results_dict[apkname]

        for new_entry in apkleaks_results:
            for old_entry in old_results:
                if new_entry['name'] == old_entry['name']:
                    merged_entry_list = list()
                    # Add results from the existing app
                    merged_entry_list.extend(old_entry['matches'])
                    # Add results from the new app
                    merged_entry_list.extend(new_entry['matches'])
                    # Eliminate duplicates
                    merged_entry_list = list(set(merged_entry_list))

                    # Add merged result to the list of all merged results
                    merged_result_entry = {'name': old_entry['name'], 'matches':merged_entry_list}
                    merged_results_list.append(merged_result_entry)

        return merged_results_list          

    def organize_sorted_apkleaks_secrets(self, apkleaks_results_with_result_length):
        print("--- Collect top most APKLeaks results from FirmwareDroid DB ---")
        firmwaredroid_apkleaks_data = dict()
        progressbar = tqdm(total=MAX_ELEMENTS)
        for apkleaks_result in apkleaks_results_with_result_length[0:MAX_ELEMENTS]:
            appname = apkleaks_result["appname"]

            progressbar.set_description("Process %s" % appname)    

            firmwaredroid_apkleaks_data[appname] = apkleaks_result["results"]

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
