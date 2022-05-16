from pymongo import MongoClient

class MongoDB(object):
    def __init__(self):
        self.client = MongoClient("localhost", 27017, username="root",
                             password="rootpassword")
        self.db = self.client["apk_scanner"]

    def store_scan(self, scans):
        collection = self.db["apkleaks_results"]
        collection.insert_one(scans)

    def get_scan_by_appname(self, appname):
        collection = self.db["apkleaks_results"]
        result = collection.find_one({"appname": appname})

        return result