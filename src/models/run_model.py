import sys
import os
import pandas as pd
from os.path import dirname, abspath, basename
project_root = dirname(dirname(abspath(__file__)))
sys.path.append(project_root)
print(project_root)
print(sys.path)
from util.preprocessor import Preprocessor
from ip_udp_heuristic import IP_UDP_Heuristic
from util.config import project_config
from ip_udp_ml import IP_UDP_ML
from sklearn.metrics import mean_absolute_error, accuracy_score
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier


if __name__ == "__main__":

    pcap_dir_path = "C:\\final_project\pcap_files\\2024_04_14_14_06_30KBps"
    labels_dir_path = "C:\\final_project\pcap_files\\2024_04_14_14_06_30KBps"

    pcap_path = "C:\\final_project\pcap_files\\2024_04_17_16_20_250KBps\pcap_2024_04_17_16_20_250KBps.csv"  # csv pcap path
    labels_path = "C:\\final_project\pcap_files\\2024_04_17_18_28_250KBps\\fpsLabels.csv"
    results_file_path = "C:\\final_project\pcap_files\\2024_04_17_16_20_250KBps\\heuristic_res_2024_04_17_16_20_250KBps.csv"

    file_tuple = (pcap_path, labels_path)   # (path to pcap file, path to labels file)
    feature_subset = [
        'SIZE',  # Size Features
        'IAT',  # Inter-Arrival Time (IAT) Features
        'LSTATS',  # Length Statistics Features
        'TSTATS',  # IAT Statistics Features
    ]

    #model = IP_UDP_Heuristic('framesReceivedPerSecond', project_config)
    model = IP_UDP_ML()
    df = model.estimate(file_tuple)
    df.to_csv(results_file_path, index=False)
