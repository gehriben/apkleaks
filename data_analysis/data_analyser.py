from tqdm import tqdm

from data_analysis.firmwaredroid_analyser import FirmwareDroidAnalyser
from data_analysis.apkleaks_analyser import ApkleaksAnalyser
from apk_scanner.db_manager import MongoDB
from apkleaks.heuristics.ping_check import PingCheck

class DataAnalyser():
    def __init__(self):
        self._firmwaredroid_analyser = FirmwareDroidAnalyser()
        self._apkleaks_analyser = ApkleaksAnalyser()
        self._db_manager = MongoDB()

    def start_analysis(self):
        # self._apkleaks_analyser.extract_secrets()
        # names = self._firmwaredroid_analyser.get_apk_names()
        # firmwaredroid_apkleaks_data = self._firmwaredroid_analyser.get_apkleaks_information_with_appnames()
        # apkleaks_apks = self._apkleaks_analyser.get_apk_names()
        
        firmwaredroid_apkleaks_data = self._firmwaredroid_analyser.get_top_most_apk_results()


        # self.compare_and_process_apks(apkleaks_apks, firmwaredroid_apkleaks_data)
        self.process_top_apks(firmwaredroid_apkleaks_data)
        self.evaluate_fp_in_ip_addresses(self._db_manager.db_name_firmwaredroid)

    def compare_and_process_apks(self, apkleaks_apks, firmwaredroid_apkleaks_data):
        stored_entries_counter = 0
        not_collected_apks = 0
        for apkleaks_apk in apkleaks_apks:
            if apkleaks_apk+'.apk' in firmwaredroid_apkleaks_data:
                results = firmwaredroid_apkleaks_data[apkleaks_apk+'.apk']
                self._apkleaks_analyser.store_appnames(self._apkleaks_analyser.db_firmwaredroid_data, results["app_id"], apkleaks_apk, results['secret_size'])
                stored_entries_counter += self.store_secrets_of_apks(results["results"], apkleaks_apk, self._apkleaks_analyser.db_firmwaredroid_data)
            else:
                not_collected_apks += 1

        print(f"Stored {stored_entries_counter} secrets from FirmwareDroid! {not_collected_apks} apks couldn't get collected!")
    
    def process_top_apks(self, firmwaredroid_apkleaks_data):
        stored_entries_counter = 0
        for appname, results in firmwaredroid_apkleaks_data.items():
            self._apkleaks_analyser.store_appnames(self._apkleaks_analyser.firmwaredroid_secrets_top_apks, results["app_id"], appname, results['secret_size'])
            stored_entries_counter += self.store_secrets_of_apks(results["results"], appname, self._apkleaks_analyser.firmwaredroid_secrets_top_apks)

        print(f"Stored {stored_entries_counter} secrets from FirmwareDroid with the top most APKs!")

    def store_secrets_of_apks(self, results, appname, db_name):
        stored_entries_counter = 0
        for result in results:
            if result["name"] != 'LinkFinder':
                for match in result["matches"]: 
                    json_object = {
                            'appname': appname,
                            'secret': match,
                            'falsePositive': False
                        }

                    self._apkleaks_analyser.store_data(db_name, result["name"], json_object)
                    stored_entries_counter += 1
        
        return stored_entries_counter

    def evaluate_fp_in_ip_addresses(self, db):
        ping_check = PingCheck()
        count = 0

        ip_addresses = list(self._db_manager.get_ip_addresses(db))
        progressbar = tqdm(total=len(ip_addresses))
        print(" --- Analysing IP Addresses if they are false positives ---")
        for ip_address in ip_addresses:
            progressbar.set_description("Trying %s" % ip_address["secret"])
            if not ping_check.check_ping(ip_address["secret"]):
                self._db_manager.update_false_positive_status_ip_address(db, ip_address["secret"])
                count += 1

            progressbar.update(1)

        print(f"Found {count} False Positve Ip Addresses")
    
    def compare_false_positives(self, db_firmware_droid, db_advanced_apkleaks):
        remaining_false_positive_secrets_dict = dict()
        removed_false_positive_secrets_dict = dict()

        firmwaredroid_collections = self._db_manager.get_collection_names(db_firmware_droid)
        advanced_apkleaks_collections = self._db_manager.get_collection_names(db_advanced_apkleaks)
        
        for firmwaredroid_collection in firmwaredroid_collections:
            if firmwaredroid_collection != "_Applist":
                if firmwaredroid_collection in advanced_apkleaks_collections:
                    firmwaredroid_entrys = self._db_manager.get_all_collection_entries(db_firmware_droid, firmwaredroid_collection)
                    advanced_apkleaks_entrys = self._db_manager.get_all_collection_entries(db_advanced_apkleaks, firmwaredroid_collection)
                    
                    remaining_false_positive_secrets, removed_false_positive_secrets = self.compare_secret_entries(firmwaredroid_entrys, advanced_apkleaks_entrys)

                    if remaining_false_positive_secrets:
                        self._db_manager.store_remaining_false_positives(remaining_false_positive_secrets)
                    if removed_false_positive_secrets:
                        self._db_manager.store_removed_false_positives(removed_false_positive_secrets)

                    remaining_false_positive_secrets_dict[firmwaredroid_collection] = remaining_false_positive_secrets
                    removed_false_positive_secrets_dict[firmwaredroid_collection] = removed_false_positive_secrets
                else:
                    firmwaredroid_entrys = self._db_manager.get_all_collection_entries(db_firmware_droid, firmwaredroid_collection)
                    removed_false_positive_secrets = self.get_removed_secrets(firmwaredroid_entrys)

                    if removed_false_positive_secrets:
                        self._db_manager.store_removed_false_positives(removed_false_positive_secrets)

                    removed_false_positive_secrets_dict[firmwaredroid_collection] = removed_false_positive_secrets


        return remaining_false_positive_secrets_dict, removed_false_positive_secrets_dict
    
    def get_removed_secrets(self, firmwaredroid_entrys, false_positives=True):
        removed_secrets = list()
        for firmwaredroid_entry in firmwaredroid_entrys:
            if firmwaredroid_entry["falsePositive"] == false_positives:
                removed_secrets.append(firmwaredroid_entry)
        
        return removed_secrets

    def compare_secret_entries(self, firmwaredroid_entrys, advanced_apkleaks_entrys, compare_false_positives=True):
        remaining_secrets = list()
        removed_secrets = list()

        print(firmwaredroid_entrys)
        for firmwaredroid_entry in firmwaredroid_entrys:
            print(firmwaredroid_entry["secret"])
            if firmwaredroid_entry["falsePositive"] == compare_false_positives:
                still_existing = False
                for advanced_apkleaks_entry in advanced_apkleaks_entrys:
                    print(" --> %s" % advanced_apkleaks_entry["secret"])
                    if firmwaredroid_entry["appname"] == advanced_apkleaks_entry["appname"] and firmwaredroid_entry["secret"] == advanced_apkleaks_entry["secret"] :
                        remaining_secrets.append(advanced_apkleaks_entry)
                        still_existing = True
                        break
                
                if not still_existing:
                    removed_secrets.append(firmwaredroid_entry)
        
        return remaining_secrets, removed_secrets

    def compare_true_positives(self, db_firmware_droid, db_advanced_apkleaks):
        remaining_true_positive_secrets_dict = dict()
        removed_true_positive_secrets_dict = dict()

        firmwaredroid_collections = self._db_manager.get_collection_names(db_firmware_droid)
        advanced_apkleaks_collections = self._db_manager.get_collection_names(db_advanced_apkleaks)
        
        for firmwaredroid_collection in firmwaredroid_collections:
            if firmwaredroid_collection != "_Applist":
                if firmwaredroid_collection in advanced_apkleaks_collections:
                    firmwaredroid_entrys = self._db_manager.get_all_collection_entries(db_firmware_droid, firmwaredroid_collection)
                    advanced_apkleaks_entrys = self._db_manager.get_all_collection_entries(db_advanced_apkleaks, firmwaredroid_collection)
                    
                    print(f"--- {firmwaredroid_collection} ---")
                    remaining_true_positive_secrets, removed_true_positive_secrets = self.compare_secret_entries(list(firmwaredroid_entrys), list(advanced_apkleaks_entrys), compare_false_positives=False)
                    
                    print(remaining_true_positive_secrets)

                    if remaining_true_positive_secrets:
                        self._db_manager.store_remaining_true_positives(remaining_true_positive_secrets)
                    if removed_true_positive_secrets:
                        self._db_manager.store_removed_true_positives(removed_true_positive_secrets)

                    remaining_true_positive_secrets_dict[firmwaredroid_collection] = remaining_true_positive_secrets
                    removed_true_positive_secrets_dict[firmwaredroid_collection] = removed_true_positive_secrets
                else:
                    firmwaredroid_entrys = self._db_manager.get_all_collection_entries(db_firmware_droid, firmwaredroid_collection)
                    removed_true_positive_secrets = self.get_removed_secrets(firmwaredroid_entrys, false_positives=False)

                    if removed_true_positive_secrets:
                        self._db_manager.store_removed_false_positives(removed_true_positive_secrets)

                    removed_true_positive_secrets_dict[firmwaredroid_collection] = removed_true_positive_secrets

        return remaining_true_positive_secrets_dict, removed_true_positive_secrets_dict

                

                        

                