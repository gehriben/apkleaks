import os
import configparser

from pymongo import MongoClient
from dotenv import load_dotenv

class MongoDB(object):
    def __init__(self):
        self.config = configparser.ConfigParser()

        load_dotenv()
        self.config.read('config.cfg')
        
        self.client = MongoClient(self.config['db']['host'], int(self.config['db']['port']), username=os.getenv('MONGO_INITDB_ROOT_USERNAME'), password=os.getenv('MONGO_INITDB_ROOT_PASSWORD'))
        self.db_advanced_apkleaks = self.client[self.config['db']['db_name']]
        self.db_advanced_apkleaks_extracted_secrets = self.client[self.config['db']['db_extracted_secrets']]
        self.db_firmwaredroid = self.client[self.config['FirmwareDroid']['db_extracted_secrets']]
        self.db_data_analysis = self.client[self.config['db']['db_data_analysis']]

        self.collection_advanced_apkleaks = self.config['db']['collection_advanced_apkleaks']

    def store_scan(self, scans):
        collection = self.db_advanced_apkleaks[self.collection_advanced_apkleaks]
        collection.insert_one(scans)

    def get_apks(self):
        collection = self.db_advanced_apkleaks[self.collection_advanced_apkleaks]
        results = collection.find({}, { "_id": 0, "appname": 1})

        return results 

    def get_advanced_apkleaks_results(self):
        collection = self.db_advanced_apkleaks[self.collection_advanced_apkleaks]
        result = collection.find({})

        return result

    def get_scan_by_appname(self, appname):
        collection = self.db_advanced_apkleaks[self.collection_advanced_apkleaks]
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

    def store_extracted_secrets(self, db, patternname, secrets):
        collection = db[patternname]
        collection.insert_one(secrets) 

    def store_appnames_of_extracted_secrets(self, db, app_id, appname, secret_size):
        collection = db['_Applist']
        collection.insert_one({"app_id":app_id, "appname": appname, "secret_size":secret_size}) 

    def store_remaining_false_positives(self, remaining_false_positives):
        collection = self.db_data_analysis["remaining_false_positves"]
        collection.insert_many(remaining_false_positives)
    
    def store_removed_false_positives(self, removed_false_positives):
        collection = self.db_data_analysis["removed_false_positives"]
        collection.insert_many(removed_false_positives)

    def store_remaining_true_positives(self, remaining_true_positives):
        collection = self.db_data_analysis["remaining_true_positves"]
        collection.insert_many(remaining_true_positives)
    
    def store_removed_true_positives(self, removed_true_positives):
        collection = self.db_data_analysis["removed_true_positives"]
        collection.insert_many(removed_true_positives)
    
    def store_newly_added_secrets(self, newly_added_secrets):
        collection = self.db_data_analysis["newly_added_secrets"]
        collection.insert_many(newly_added_secrets)
    
    def get_all_app_informations(self):
        collection = self.db_firmwaredroid["_Applist"]
        result = collection.find({}, { 'app_id': 1, 'appname': 1, '_id':0})

        return result
