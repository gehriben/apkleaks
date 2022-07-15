from pymongo import MongoClient

COLLECTION_NAME = "apkleaks_results_v7"

class ApkleaksAnalyser():
    def __init__(self):
        self.client = MongoClient("mongodb", 27017, username="root", password="rootpassword")
        self.db = self.client["apk_scanner"]
        self.db_apk_scanner_secrets = self.client["apk_scanner_secrets"]
        self.db_firmwaredroid_data = self.client["firmwaredroid_secrets"]
        self.firmwaredroid_secrets_top_apks = self.client["firmwaredroid_secrets_top_apks"]

    def get_apk_names(self):
        apk_names = self.get_apks()

        apk_list = list()
        for apk_name in apk_names:
            if apk_name["appname"] not in apk_list:
                apk_list.append(apk_name["appname"])

        print(len(apk_list))
        
        return apk_list
    
    def get_apks(self):
        collection = self.db["apkleaks_results"]
        results = collection.find({}, { "_id": 0, "appname": 1})

        return results 
    
    def extract_secrets(self):
        data = self.get_data()

        secret_counter = 0
        for entry in data:
            secret_counter_per_app = 0
            for result in entry["packages"]["results"]:
                for patternname, value in result.items():
                    if 'valid_secrets' in value:
                        for secret in value["valid_secrets"]:
                            json_object = {
                                'appname': entry['appname'] if entry['appname'].endswith(".apk") else entry['appname']+".apk",
                                'secret': secret['secret'],
                                'score': secret['score']
                            }

                            self.store_data(self.db_apk_scanner_secrets, patternname, json_object)
                            secret_counter += 1
                            secret_counter_per_app += 1
            
            app_json_object = {
                'appname': entry['appname'] if entry['appname'].endswith(".apk") else entry['appname']+".apk",
                'secret_size': secret_counter_per_app
            }

            self.store_data(self.db_apk_scanner_secrets, "_Applist", app_json_object)
                    
        print(f"Extraced and stored valid secrets! Found {secret_counter} secrets in total.")
        
    def store_data(self, db, patternname, secrets):
        collection = db[patternname]
        collection.insert_one(secrets) 

    def store_appnames(self, db, app_id, appname, secret_size):
        collection = db['_Applist']
        collection.insert_one({"app_id":app_id, "appname": appname, "secret_size":secret_size}) 

    def get_data(self):
        collection = self.db[COLLECTION_NAME]
        result = collection.find({})

        return result
