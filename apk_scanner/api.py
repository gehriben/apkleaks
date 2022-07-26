import requests
import os
import configparser

from tqdm import tqdm
from dotenv import load_dotenv

from apk_scanner.db_manager import MongoDB

APK_PATH = '../apks/apk_files'

class API():
    def __init__(self):
        self.mongodb = MongoDB()
        self.config = configparser.ConfigParser()

        load_dotenv()
        self.config.read('config.cfg')
        self.base_url = self.config['FirmwareDroid']['api_url']
        self.cookie = {'access_token_cookie': os.getenv('FIRMWAREDROID_COOKIE') }
        self.apk_path = '..' + self.config['AdvancedAPKLeaks']['mountpoint'] + self.config['AdvancedAPKLeaks']['apk_folder']

    def get_all_apks(self):
        app_informations = list(self.mongodb.get_all_app_informations())
        
        print("--- Fetches and stores required apks ---")
        progressbar = tqdm(total=len(app_informations))
        for app_info in app_informations:
            if not os.path.exists(self.apk_path+'/'+app_info['appname']): 
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