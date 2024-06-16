import os
import time
import sys
from os.path import dirname, abspath, basename
project_root = dirname(dirname(abspath(__file__)))
sys.path.append(project_root)
print(project_root)
print(sys.path)
from run_model_v2 import ModelRunner
from util.helper_functions import create_file_tuples_list



if __name__ == '__main__':

    metric = 'fps'
    estimation_method = 'ip-udp-ml'
    feature_subset = ['LSTATS', 'TSTATS']
    data_dir = "C:\\final_project\pcap_files"
    my_ip = '10.100.102.32'

    model_runner = ModelRunner(metric, estimation_method, feature_subset, data_dir, 1, my_ip)
    #file_tuples_list = create_file_tuples_list("C:\\final_project\pcap_files", metric)
    #target_files = ("C:\\final_project\pcap_files\\2024_04_14_14_06_30KBps\pcap_2024_04_14_14_06_30KBps.csv",
    #                "C:\\final_project\pcap_files\\2024_04_14_14_06_30KBps\\fpsLabels.csv")
    vca_model = model_runner.load_intermediate("fps_ip-udp-ml_LSTATS-TSTATS_pcap_files_cv_1_vca_model")

    # estimate
    file_tuples_list_test = create_file_tuples_list("C:\\final_project\pcap_files_test", metric)
    # vca_model.estimate(target_files)
    predictions = model_runner.get_test_set_predictions(file_tuples_list_test, vca_model)
    print("---------")