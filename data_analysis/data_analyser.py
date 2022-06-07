from pymongo import MongoClient

COLLECTION_NAME = "apkleaks_results_v2"

class DataAnalyser():
    def __init__(self):
        self.client = MongoClient("mongodb", 27017, username="root",
                             password="rootpassword")
        self.db_apk_scanner = self.client["apk_scanner"]
        self.db_apk_scanner_secrets = self.client["apk_scanner_secrets"]

    def analyse_data(self):
        data = self.get_data()

        secret_counter = 0
        for entry in data:
            for result in entry["packages"]["results"]:
                for patternname, value in result.items():
                    for secret in value["valid_secrets"]:
                        json_object = {
                            'appname': entry['appname'],
                            'secret': secret['secret'],
                            'score': secret['score']
                        }

                        self.store_data(patternname, json_object)
                        secret_counter += 1
                    
        print(f"Extraced and stored valid secrets! Found {secret_counter} secrets in total.")
        
    def store_data(self, patternname, secrets):
        collection = self.db_apk_scanner_secrets[patternname]
        collection.insert_one(secrets)  

    def get_data(self):
        collection = self.db_apk_scanner[COLLECTION_NAME]
        result = collection.find({})

        return result

