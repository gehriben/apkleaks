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

        self.process_apks(firmwaredroid_apkleaks_data, apkleaks_apks)

    def process_apks(self, apkleaks_apks, firmwaredroid_apkleaks_data):
        stored_entries_counter = 0
        not_collected_apks = 0
        for apkleaks_apk in apkleaks_apks:
            if apkleaks_apk in firmwaredroid_apkleaks_data:
                results = firmwaredroid_apkleaks_data[apkleaks_apk]
                stored_entries_counter += self.store_overlap_apks(results, apkleaks_apk)
            else:
                not_collected_apks += 1

        print(f"Stored {stored_entries_counter} secrets from FirmwareDroid! {not_collected_apks} apks couldn't get collected!")
                

    def store_overlap_apks(self, results, appname):
        stored_entries_counter = 0
        for result in results:
            for match in result["matches"]: 
                json_object = {
                        'appname': appname,
                        'secret': match,
                        'falsePositive': None
                    }

                self._apkleaks_analyser.store_data(self._apkleaks_analyser.db_firmwaredroid_data, result["name"], json_object)
                stored_entries_counter += 1
        
        return stored_entries_counter