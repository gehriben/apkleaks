import matplotlib.pyplot as plt

from pymongo import MongoClient

from apk_scanner.db_manager import MongoDB
from data_analysis.data_analyser import DataAnalyser

PLOT_PATH = '../apks/plots'

class DataVisualisation():
    def __init__(self):
        self.db_manager = MongoDB()
        self.data_analyser = DataAnalyser()

        self.false_positive_names = []
        self.false_positive_count = []

    def start_visualistaion(self):
        self.show_secret_distribution(self.db_manager.db_name_firmwaredroid)
        self.show_false_positive_distribution(self.db_manager.db_name_firmwaredroid)
        self.show_false_positive_difference()

    def show_secret_distribution(self, db):
        secret_names = []
        secret_count = []

        for collection in self.db_manager.get_collection_names(db):
            if collection != "_Applist":
                content_count = self.db_manager.get_document_count(db, collection)
                secret_names.append(collection)
                secret_count.append(content_count)

        plt.figure(figsize=(30, 20))
        bar = plt.bar(secret_names, secret_count)
        plt.title("Secret distribution over pattern types")
        plt.bar_label(bar)
        plt.savefig(PLOT_PATH+'/secret_distribution.png', width=0.3, bbox_inches='tight')

    def show_false_positive_distribution(self, db):
        for collection in self.db_manager.get_collection_names(db):
            if collection != "_Applist":
                content_count = self.db_manager.get_false_positive_count(db, collection)
                self.false_positive_names.append(collection)
                self.false_positive_count.append(content_count)


        plt.figure(figsize=(30, 20))
        bar = plt.bar(self.false_positive_names, self.false_positive_count)
        plt.title("False Positive distribution over pattern types")
        plt.bar_label(bar)
        plt.savefig(PLOT_PATH+'/false_positive_distribution.png', width=0.3, bbox_inches='tight')

    def show_false_positive_difference(self):
        remaining_false_positive_secrets_dict, removed_false_positive_secrets_dict = self.data_analyser.compare_false_positivs(self.db_manager.db_name_firmwaredroid, self.db_manager.db_name_advanced_apkleaks)

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
        plt.savefig(PLOT_PATH+'/false_positive_difference.png')

        removed_false_positive_secrets_names = []
        removed_false_positive_secrets_content = []
        for pattern_name, content in removed_false_positive_secrets_dict.items():
            removed_false_positive_secrets_names.append(pattern_name)
            removed_false_positive_secrets_content.append(len(content))

        plt.figure(figsize=(30, 20))
        bar = plt.bar(removed_false_positive_secrets_names, removed_false_positive_secrets_content)
        plt.title("Removed False Positive pattern distribution")
        plt.bar_label(bar)
        plt.savefig(PLOT_PATH+'/removed_false_positive.png', width=0.3, bbox_inches='tight')


        remaining_false_positive_secrets_names = []
        remaining_false_positive_secrets_content = []
        for pattern_name, content in remaining_false_positive_secrets_dict.items():
            remaining_false_positive_secrets_names.append(pattern_name)
            remaining_false_positive_secrets_content.append(len(content))

        plt.figure(figsize=(30, 20))
        bar = plt.bar(remaining_false_positive_secrets_names, remaining_false_positive_secrets_content)
        plt.title("Remaining False Positive pattern distribution")
        plt.bar_label(bar)
        plt.savefig(PLOT_PATH+'/remaining_false_positive.png', width=0.3, bbox_inches='tight')


if __name__ == '__main__':
    data_visualiser = DataVisualisation()
    data_visualiser.start_visualistaion()