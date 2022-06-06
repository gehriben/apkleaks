from pymongo import MongoClient

COLLECTION_NAME = "apkleaks_results"

class MongoDB(object):
    def __init__(self):
        self.client = MongoClient("mongodb", 27017, username="root",
                             password="rootpassword")
        self.db = self.client["apk_scanner"]

    def store_scan(self, scans):
        collection = self.db[COLLECTION_NAME]
        collection.insert_one(scans)

    def get_scan_by_appname(self, appname):
        collection = self.db[COLLECTION_NAME]
        result = collection.find_one({"appname": appname})

        return result