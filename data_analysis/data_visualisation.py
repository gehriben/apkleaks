import matplotlib.pyplot as plt
import configparser
import os

from pymongo import MongoClient

from apk_scanner.db_manager import MongoDB
from data_analysis.data_analyser import DataAnalyser
from data_analysis.apkleaks_analyser import ApkleaksAnalyser

class DataVisualisation():
    def __init__(self):
        self.db_manager = MongoDB()
        self.data_analyser = DataAnalyser()
        self.apkleaks_analyser = ApkleaksAnalyser()
        self.config = configparser.ConfigParser()
        
        self.config.read('config.cfg')
        self.plot_path =  '..' + self.config['AdvancedAPKLeaks']['mountpoint'] + self.config['AdvancedAPKLeaks']['plot_folder']

    def start_visualistaion(self):
        if not os.path.exists(self.plot_path):
            os.mkdir(self.plot_path)

        self.show_secret_distribution(self.db_manager.db_firmwaredroid, self.db_manager.db_advanced_apkleaks_extracted_secrets)
        
        if self.config['AdvancedAPKLeaks']['include_firmware_droid_data'] == 'true':
            self.show_false_positive_distribution()
            self.show_false_positive_difference()
            self.show_true_positive_difference()
            self.show_newly_added_secrets()
            self.apkleaks_analyser.analyse_effectivness_of_heuristic()

    def show_secret_distribution(self, firmwaredroid_db, advanced_apkleaks_db):
        secret_names = []
        secret_count = []

        if self.config['AdvancedAPKLeaks']['include_firmware_droid_data'] == 'true':
            #Old APKLeaks
            for collection in self.db_manager.get_collection_names(firmwaredroid_db):
                if collection != "_Applist":
                    content_count = self.db_manager.get_document_count(firmwaredroid_db, collection)
                    secret_names.append(collection)
                    secret_count.append(content_count)

            plt.figure(figsize=(12, 5))
            bar = plt.barh(secret_names, secret_count)
            plt.title("Secret distribution over pattern types in original APKLeaks")
            plt.bar_label(bar, padding=10)
            plt.savefig(self.plot_path+'/secret_distribution_old_apkleaks.png', height=0.5, bbox_inches='tight')

        secret_names = []
        secret_count = []

        # New AdvancedAPKLeaks
        for collection in self.db_manager.get_collection_names(advanced_apkleaks_db):
            if collection != "_Applist":
                content_count = self.db_manager.get_document_count(advanced_apkleaks_db, collection)
                secret_names.append(collection)
                secret_count.append(content_count)

        plt.figure(figsize=(12, 5))
        bar = plt.barh(secret_names, secret_count)
        plt.title("Secret distribution over pattern types in AdvancedAPKLeaks")
        plt.bar_label(bar, padding=10)
        plt.savefig(self.plot_path+'/secret_distribution_new_apkleaks.png', width=0.3, bbox_inches='tight')

    def show_false_positive_distribution(self):
        db = self.db_manager.db_firmwaredroid
        self.false_positive_names = []
        self.false_positive_count = []

        for collection in self.db_manager.get_collection_names(db):
            if collection != "_Applist":
                content_count = self.db_manager.get_false_positive_count(db, collection)
                self.false_positive_names.append(collection)
                self.false_positive_count.append(content_count)


        plt.figure(figsize=(12, 5))
        bar = plt.barh(self.false_positive_names, self.false_positive_count)
        plt.title("False positive distribution over pattern types in original APKLeaks")
        plt.bar_label(bar, padding=10)
        plt.savefig(self.plot_path+'/false_positive_distribution_old_apkleaks.png', width=0.3, bbox_inches='tight')

        db = self.db_manager.db_advanced_apkleaks_extracted_secrets
        self.false_positive_names = []
        self.false_positive_count = []

        for collection in self.db_manager.get_collection_names(db):
            if collection != "_Applist":
                content_count = self.db_manager.get_false_positive_count(db, collection)
                self.false_positive_names.append(collection)
                self.false_positive_count.append(content_count)


        plt.figure(figsize=(12, 5))
        bar = plt.barh(self.false_positive_names, self.false_positive_count)
        plt.title("False positive distribution over pattern types in AdvancedAPKLeaks")
        plt.bar_label(bar, padding=10)
        plt.savefig(self.plot_path+'/false_positive_distribution_new_apkleaks.png', width=0.3, bbox_inches='tight')

    def show_false_positive_difference(self):
        remaining_false_positive_secrets_dict, removed_false_positive_secrets_dict = self.data_analyser.compare_false_positives(self.db_manager.db_firmwaredroid, self.db_manager.db_advanced_apkleaks_extracted_secrets)

        total_false_positive_secrets = sum(self.false_positive_count)
        total_remaining_false_positives = sum(len(lst) for lst in remaining_false_positive_secrets_dict.values())
        total_removed_false_positive_secrets= sum(len(lst) for lst in removed_false_positive_secrets_dict.values())

        column_header = ('Description', 'Value')

        values = [['Total_False_Positives', total_false_positive_secrets],
                  ['Remaining_False_Positives', total_remaining_false_positives],
                  ['Removed_False_Positives', total_removed_false_positive_secrets]
        ]

        fig, ax = plt.subplots()
        # hide axes
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')

        ax.table(cellText=values, colLabels=column_header)
        fig.tight_layout()
        plt.savefig(self.plot_path+'/false_positive_difference.png')

        removed_false_positive_secrets_names = []
        removed_false_positive_secrets_content = []
        for pattern_name, content in removed_false_positive_secrets_dict.items():
            removed_false_positive_secrets_names.append(pattern_name)
            removed_false_positive_secrets_content.append(len(content))

        plt.figure(figsize=(12, 5))
        bar = plt.barh(removed_false_positive_secrets_names, removed_false_positive_secrets_content)
        plt.title("Removed false positive pattern distribution")
        plt.bar_label(bar, padding=10)
        plt.savefig(self.plot_path+'/removed_false_positive.png', width=0.3, bbox_inches='tight')


        remaining_false_positive_secrets_names = []
        remaining_false_positive_secrets_content = []
        for pattern_name, content in remaining_false_positive_secrets_dict.items():
            remaining_false_positive_secrets_names.append(pattern_name)
            remaining_false_positive_secrets_content.append(len(content))

        plt.figure(figsize=(12, 5))
        bar = plt.barh(remaining_false_positive_secrets_names, remaining_false_positive_secrets_content)
        plt.title("Remaining false positive pattern distribution")
        plt.bar_label(bar, padding=10)
        plt.savefig(self.plot_path+'/remaining_false_positive.png', width=0.3, bbox_inches='tight')
    
    def show_true_positive_difference(self):
        remaining_true_positive_secrets_dict, removed_true_positive_secrets_dict = self.data_analyser.compare_true_positives(self.db_manager.db_firmwaredroid, self.db_manager.db_advanced_apkleaks_extracted_secrets)

        removed_true_positive_secrets_names = []
        removed_true_positive_secrets_content = []
        for pattern_name, content in removed_true_positive_secrets_dict.items():
            removed_true_positive_secrets_names.append(pattern_name)
            removed_true_positive_secrets_content.append(len(content))

        plt.figure(figsize=(12, 5))
        bar = plt.barh(removed_true_positive_secrets_names, removed_true_positive_secrets_content)
        plt.title("Removed true positive pattern distribution")
        plt.bar_label(bar, padding=10)
        plt.savefig(self.plot_path+'/removed_true_positive.png', width=0.3, bbox_inches='tight')


        remaining_true_positive_secrets_names = []
        remaining_true_positive_secrets_content = []
        for pattern_name, content in remaining_true_positive_secrets_dict.items():
            remaining_true_positive_secrets_names.append(pattern_name)
            remaining_true_positive_secrets_content.append(len(content))

        plt.figure(figsize=(12, 5))
        bar = plt.barh(remaining_true_positive_secrets_names, remaining_true_positive_secrets_content)
        plt.title("Remaining true positive pattern distribution")
        plt.bar_label(bar, padding=10)
        plt.savefig(self.plot_path+'/remaining_true_positive.png', width=0.3, bbox_inches='tight')
    
    def show_newly_added_secrets(self):
        newly_added_secrets_dict = self.apkleaks_analyser.get_newly_added_secrets(self.db_manager.db_firmwaredroid, self.db_manager.db_advanced_apkleaks_extracted_secrets)

        newly_added_secrets_names = []
        newly_added_secrets_content = []
        for pattern_name, content in newly_added_secrets_dict.items():
            newly_added_secrets_names.append(pattern_name)
            newly_added_secrets_content.append(len(content))

        plt.figure(figsize=(12, 5))
        bar = plt.barh(newly_added_secrets_names, newly_added_secrets_content)
        plt.title("Newly added secrets")
        plt.bar_label(bar, padding=10)
        plt.savefig(self.plot_path+'/newly_added_secrets.png', width=0.3, bbox_inches='tight')


if __name__ == '__main__':
    data_visualiser = DataVisualisation()
    data_visualiser.start_visualistaion()