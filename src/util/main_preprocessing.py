import sys
import os
from os.path import dirname, abspath, basename
project_root = dirname(dirname(abspath(__file__)))
sys.path.append(project_root)
print(project_root)
print(sys.path)
from preprocessor import Preprocessor

if __name__ == "__main__":

    pcap_dir_path = "C:\\final_project\\final_pcap_files"
    labels_dir_path = "C:\\final_project\labels_csv"

    #pcap_path = 'C:\\final_project\\data files\\2024_02_13_15_00_29\\pcap_2024_02_13_15_00_29.csv'
    #labels_path = 'C:\\final_project\\data files\\2024_02_13_15_00_29\\labels_2024_02_13_15_00_29.csv'
    pcap_path = "C:\\final_project\pcap_files\\2024_04_17_18_28_250KBps\pcap_2024_04_17_18_28_250KBps.csv"
    labels_path = "C:\\final_project\pcap_files\\2024_04_17_18_28_250KBps\\fpsLabels.csv"

    feature_subset = [
        #'SIZE',  # Size Features
        #'IAT',  # Inter-Arrival Time (IAT) Features
        'LSTATS',  # Length Statistics Features
        'TSTATS',  # IAT Statistics Features
    ]

    file_tuples = [(pcap_path, labels_path)]
    my_ip = '192.198.0.101'

proc = Preprocessor(feature_subset, my_ip)
proc.process_input(file_tuples)
