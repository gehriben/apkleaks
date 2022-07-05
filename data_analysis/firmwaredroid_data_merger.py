from tqdm import tqdm

class FirmwaredroidDataMerger():
    def __init__(self):
        pass

    def check_firmwaredroid_data_for_merges(self, apkleaks_results_with_appnames, max_output_limit) -> dict():
        print("--- Merge apkleaks results with same appname together ---")
        appnames_with_apkleaks_results_dict = dict()
        progressbar = tqdm(total=max_output_limit)
        for entry in apkleaks_results_with_appnames:
            if entry["android_app"]:
                app_id = entry['android_app'][0]['_id']
                apkname = entry['android_app'][0]['filename']
                apkleaks_results = entry['results']['results']

                if apkname in appnames_with_apkleaks_results_dict:
                    progressbar.set_description("Merging %s" % apkname)

                    merged_results = self.merge_apkleaks_results(appnames_with_apkleaks_results_dict, apkname, apkleaks_results)
                    appnames_with_apkleaks_results_dict[apkname] = {'app_id': app_id, 'results': merged_results }
                else:
                    progressbar.set_description("Adding %s" % apkname)

                    appnames_with_apkleaks_results_dict[apkname] = {'app_id': app_id, 'results': apkleaks_results }

            progressbar.update(1)
        
        return appnames_with_apkleaks_results_dict

    def merge_apkleaks_results(self, appnames_with_apkleaks_results_dict, apkname, apkleaks_results) -> list():
        merged_results_list = list()

        old_results = appnames_with_apkleaks_results_dict[apkname]

        for new_entry in apkleaks_results:
            for old_entry in old_results["results"]:
                if new_entry['name'] == old_entry['name']:
                    merged_entry_list = list()
                    # Add results from the existing app
                    merged_entry_list.extend(old_entry['matches'])
                    # Add results from the new app
                    merged_entry_list.extend(new_entry['matches'])
                    # Eliminate duplicates
                    merged_entry_list = list(set(merged_entry_list))

                    # Add merged result to the list of all merged results
                    merged_result_entry = {'name': old_entry['name'], 'matches':merged_entry_list}
                    merged_results_list.append(merged_result_entry)

        return merged_results_list        