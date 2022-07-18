import requests
import os

from tqdm import tqdm

from apk_scanner.db_manager import MongoDB

BASE_URL = "https://firmwaredroid.cloudlab.zhaw.ch/api"
COOKIE = {'access_token_cookie': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY1ODEyNjQ1MSwianRpIjoiZjQ0M2JlM2MtZmE5NS00MDNkLWE0Y2QtZjNmM2MzMzQxZjVkIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6IntcInJvbGVfbGlzdFwiOiBbXCJ1c2VyXCJdLCBcImVtYWlsXCI6IFwiZ2VobkB6aGF3LmNoXCJ9IiwibmJmIjoxNjU4MTI2NDUxLCJleHAiOjE2NTg3MzEyNTF9.4bj6huXJ0g2z4lrW7uS2VCSzWTZETdBCWqFj6yrhBlU'}
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
                print(app_info['appname']+" already downloaded! Skipping!")

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