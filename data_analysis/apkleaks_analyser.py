from apk_scanner.db_manager import MongoDB

class ApkleaksAnalyser():
    def __init__(self):
        self._db_manager = MongoDB()

    def get_apk_names(self):
        apk_names = self._db_manager.get_apks()

        apk_list = list()
        for apk_name in apk_names:
            if apk_name["appname"] not in apk_list:
                apk_list.append(apk_name["appname"])

        print(len(apk_list))
        
        return apk_list
    
    def extract_secrets(self):
        data = self._db_manager.get_advanced_apkleaks_results()

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
                                'score': secret['score'],
                                'falsePositive': False
                            }

                            self._db_manager.store_extracted_secrets(self._db_manager.db_advanced_apkleaks_extracted_secrets, patternname, json_object)
                            secret_counter += 1
                            secret_counter_per_app += 1
            
            app_json_object = {
                'appname': entry['appname'] if entry['appname'].endswith(".apk") else entry['appname']+".apk",
                'secret_size': secret_counter_per_app
            }

            self._db_manager.store_extracted_secrets(self._db_manager.db_advanced_apkleaks_extracted_secrets, "_Applist", app_json_object)
                    
        print(f"Extraced and stored valid secrets! Found {secret_counter} secrets in total.")
    
    def get_newly_added_secrets(self, db_firmware_droid, db_advanced_apkleaks):
        newly_added_secrets_dict = dict()

        firmwaredroid_collections = self._db_manager.get_collection_names(db_firmware_droid)
        advanced_apkleaks_collections = self._db_manager.get_collection_names(db_advanced_apkleaks)
        
        for advanced_apkleaks_collection in advanced_apkleaks_collections:
            if advanced_apkleaks_collection != "_Applist":
                if advanced_apkleaks_collection in firmwaredroid_collections:
                    firmwaredroid_entrys = self._db_manager.get_all_collection_entries(db_firmware_droid, advanced_apkleaks_collection)
                    advanced_apkleaks_entrys = self._db_manager.get_all_collection_entries(db_advanced_apkleaks, advanced_apkleaks_collection)
                    
                    newly_added_secrets = self.get_newly_added_secrets_in_collection(advanced_apkleaks_entrys, firmwaredroid_entrys, advanced_apkleaks_collection)

                    if newly_added_secrets:
                        self._db_manager.store_newly_added_secrets(newly_added_secrets)

                    newly_added_secrets_dict[advanced_apkleaks_collection] = newly_added_secrets
                else:
                    advanced_apkleaks_entrys = list(self._db_manager.get_all_collection_entries(db_advanced_apkleaks, advanced_apkleaks_collection))

                    if advanced_apkleaks_entrys:
                        self._db_manager.store_newly_added_secrets(advanced_apkleaks_entrys)

                    newly_added_secrets_dict[advanced_apkleaks_collection] = advanced_apkleaks_entrys


        return newly_added_secrets_dict

    def get_newly_added_secrets_in_collection(self, advanced_apkleaks_entrys, firmwaredroid_entrys, secret_type):
        firmwaredroid_entrys = list(firmwaredroid_entrys)
        advanced_apkleaks_entrys = list(advanced_apkleaks_entrys)
        
        new_secrets = list()

        for advanced_apkleaks_entry in advanced_apkleaks_entrys:
            is_new = True
            for firmwaredroid_entry in firmwaredroid_entrys:
                if advanced_apkleaks_entry["appname"] == firmwaredroid_entry["appname"] and advanced_apkleaks_entry["secret"] in firmwaredroid_entry["secret"]:
                    is_new = False
                    break
            
            if is_new:
                advanced_apkleaks_entry['secret_type'] = secret_type
                new_secrets.append(advanced_apkleaks_entry)
        
        return new_secrets

    def analyse_effectivness_of_heuristic(self):
        count_classifications = dict()

        app_list = list(self._db_manager.get_all_collection_entries(self._db_manager.db_advanced_apkleaks, self._db_manager.collection_advanced_apkleaks))
        
        for heuristic_name in ('entropy_calculator', 'keyword_searcher', 'import_extractor', 'ping_check', 'word_filter'):
            print(f"--- Results for {heuristic_name} heuristic ---")
            for app in app_list:
                results = app["packages"]["results"]
                for result in results:
                    for pattern_name, heuristic in result.items():
                        valid_secrets = list()
                        heuristic_results = list()

                        if not pattern_name in count_classifications:
                            count_classifications[pattern_name] = {'total_analysed_secrets': 0, 'total_classificatons': 0, 'correct_classificatons': 0, 'wrong_classificatons':0}

                        if 'valid_secrets' in  heuristic:
                            valid_secrets = heuristic["valid_secrets"]

                        if heuristic_name in heuristic:
                            heuristic_results = heuristic[heuristic_name]
                            count_classifications[pattern_name]['total_analysed_secrets'] += len(heuristic_results)

                        for valid_secret in valid_secrets:
                            index = valid_secret['index']
                            if heuristic_results:
                                if 'score' in heuristic_results[index]:
                                    if heuristic_results[index]['score'] != 0:
                                        count_classifications[pattern_name]['correct_classificatons'] += 1
                                    else:
                                        count_classifications[pattern_name]['wrong_classificatons'] += 1
                                else:
                                    count_classifications[pattern_name]['wrong_classificatons'] += 1  

                        for heuristic_result in heuristic_results:
                            if 'score' in heuristic_result:
                                if heuristic_result['score'] != 0:
                                    count_classifications[pattern_name]['total_classificatons'] += 1
            
            total_secrets = 0
            total_classifcations = 0
            total_correct_classifcations = 0
            total_wrong_classifcations = 0
            for pattern_name, count_classification in count_classifications.items():
                total_secrets += count_classification['total_analysed_secrets']
                total_classifcations += count_classification['total_classificatons']
                total_correct_classifcations += count_classification['correct_classificatons']
                total_wrong_classifcations += count_classification['wrong_classificatons']


                print(f" {pattern_name}")
                print(f"  --> Total analysed secrets: {count_classification['total_analysed_secrets']}")
                print(f"  --> Total classifcations: {count_classification['total_classificatons']}")
                print(f"  --> Total correct classifcations: {count_classification['correct_classificatons']}") 
                print(f"  --> Total wrong classifcations: {count_classification['wrong_classificatons']}") 
            
            print(" Overall")
            print(f"  --> Total analysed secrets: {total_secrets}")
            print(f"  --> Total classifcations: {total_classifcations}")
            print(f"  --> Total correct classifcations: {total_correct_classifcations}")
            print(f"  --> Total wrong classifcations: {total_wrong_classifcations}") 
