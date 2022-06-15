from data_analysis.firmwaredroid_analyser import FirmwareDroidAnalyser
from data_analysis.apkleaks_analyser import ApkleaksAnalyser

class DataAnalyser():
    def __init__(self):
        self._firmwaredroid_analyser = FirmwareDroidAnalyser()
        self._apkleaks_analyser = ApkleaksAnalyser()

    def start_analysis(self):
        # self._apkleaks_analyser.extract_secrets()
        # names = self._firmwaredroid_analyser.get_apk_names()
        firmwaredroid_apkleaks_data = self._firmwaredroid_analyser.get_apkleaks_information_with_appnames()
        apkleaks_apks = self._apkleaks_analyser.get_apk_names()
        
        # firmwaredroid_apkleaks_data = self._firmwaredroid_analyser.get_top_most_apk_results()


        self.compare_and_process_apks(apkleaks_apks, firmwaredroid_apkleaks_data)
        # self.process_top_apks(firmwaredroid_apkleaks_data)

    def compare_and_process_apks(self, apkleaks_apks, firmwaredroid_apkleaks_data):
        stored_entries_counter = 0
        not_collected_apks = 0
        for apkleaks_apk in apkleaks_apks:
            if apkleaks_apk+'.apk' in firmwaredroid_apkleaks_data:
                results = firmwaredroid_apkleaks_data[apkleaks_apk+'.apk']
                self._apkleaks_analyser.store_appnames(self._apkleaks_analyser.db_firmwaredroid_data, apkleaks_apk, results['secret_size'])
                stored_entries_counter += self.store_secrets_of_apks(results["results"], apkleaks_apk, self._apkleaks_analyser.db_firmwaredroid_data)
            else:
                not_collected_apks += 1

        print(f"Stored {stored_entries_counter} secrets from FirmwareDroid! {not_collected_apks} apks couldn't get collected!")
    
    def process_top_apks(self, firmwaredroid_apkleaks_data):
        stored_entries_counter = 0
        for appname, results in firmwaredroid_apkleaks_data.items():
            self._apkleaks_analyser.store_appnames(self._apkleaks_analyser.firmwaredroid_secrets_top_apks, appname, results['secret_size'])
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