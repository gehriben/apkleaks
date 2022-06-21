from pymongo import MongoClient

COLLECTION_NAME = "apkleaks_results_v2"

class MongoDB(object):
    def __init__(self):
        self.client = MongoClient("mongodb", 27017, username="root", password="rootpassword")
        self.db_apk_scanner = self.client["apk_scanner"]
        self.db_name_advanced_apkleaks = self.client["apk_scanner_secrets"]
        self.db_name_firmwaredroid = self.client["firmwaredroid_secrets"]
        self.db_name_data_analisation = self.client["data_analisation"]

    def store_scan(self, scans):
        collection = self.db_apk_scanner[COLLECTION_NAME]
        collection.insert_one(scans)

    def get_scan_by_appname(self, appname):
        collection = self.db_apk_scanner[COLLECTION_NAME]
        result = collection.find_one({"appname": appname})

        return result
    
    def get_collection_names(self, db):
        return db.list_collection_names()

    def get_document_count(self, db, collection_name):
        collection = db[collection_name]
        results = collection.find({})
        results_count = len(list(results))
        return results_count
    
    def get_false_positive_count(self, db, collection_name):
        collection = db[collection_name]
        results = collection.find({'falsePositive':True})
        results_count = len(list(results))
        return results_count
    
    def get_ip_addresses(self, db):
        collection = db["IP_Address"]
        result = collection.find({})

        return result

    def update_false_positive_status_ip_address(self, db, ip_address):
        collection = db["IP_Address"]
        collection.update({"secret": ip_address}, {"$set":{ "falsePositive": True}})

    def get_all_collection_entries(self, db, collection):
        collection = db[collection]
        result = collection.find({}, {'_id':0})

        return result

    def store_remaining_false_positives(self, remaining_false_positives):
        collection = self.db_name_data_analisation["remaining_false_positves"]
        collection.insert_many(remaining_false_positives)
    
    def store_removed_false_positives(self, removed_false_positives):
        collection = self.db_name_data_analisation["removed_false_positives"]
        collection.insert_many(removed_false_positives)

    def store_remaining_true_positives(self, remaining_true_positives):
        collection = self.db_name_data_analisation["remaining_true_positves"]
        collection.insert_many(remaining_true_positives)
    
    def store_removed_true_positives(self, removed_true_positives):
        collection = self.db_name_data_analisation["removed_true_positives"]
        collection.insert_many(removed_true_positives)
