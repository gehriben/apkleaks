import requests
import os

from tqdm import tqdm

from apk_scanner.db_manager import MongoDB

BASE_URL = "https://firmwaredroid.cloudlab.zhaw.ch/api"
COOKIE = {'access_token_cookie': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY1NzYxOTI2MywianRpIjoiNGRiNGFlOWEtMWMyZi00YWM4LWFmMmYtMzNkNWU1M2MxNmEzIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6IntcInJvbGVfbGlzdFwiOiBbXCJ1c2VyXCJdLCBcImVtYWlsXCI6IFwiZ2VobkB6aGF3LmNoXCJ9IiwibmJmIjoxNjU3NjE5MjYzLCJleHAiOjE2NTgyMjQwNjN9.7AewcRoZ-3VHwxbk5f6QxvpWGeW_QcTGw-RWH15EU1c'}
APK_PATH = '../apks/apk_files'

class API():
    def __init__(self):
        self.base_url = BASE_URL
        self.cookie = COOKIE
        self.mongodb = MongoDB()

    def get_all_apks(self):
        app_informations = list(self.mongodb.get_all_app_informations())
        
        print("--- Fetches and stores required apks ---")
        progressbar = tqdm(total=len(app_informations))
        for app_info in app_informations:
            if not os.path.exists(APK_PATH+'/'+app_info['appname']): 
                progressbar.set_description("Fetch and store %s" % app_info['appname'])    
                apk = self.get_apk(app_info['app_id'])
                self.store_apk(app_info['appname'], apk)
                progressbar.update(1)
            else:
                print("APK already downloaded! Skipping!")

    def get_apk(self, app_id):
        result = requests.get(self.base_url + "/v1/android_app/download/" + str(app_id), cookies=self.cookie, verify=False)
        return result.content
    
    def store_apk(self, appname, apk):
        with open(APK_PATH+'/'+appname, 'wb') as f:
            f.write(apk)
    
    def is_download_possible(self, app_id):
        result = requests.get(self.base_url + "/v1/android_app/download/" + str(app_id), cookies=self.cookie, verify=False)
        if result.status_code == 200:
            return True
        else:
            return False