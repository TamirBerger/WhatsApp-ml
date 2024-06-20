import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
import os
import time
import sys
from os.path import dirname, abspath
d = dirname(dirname(abspath(__file__)))
sys.path.append(d)
from util.feature_extraction import FeatureExtractor
from util.config import project_config



class DataAnalyzer:

    def __init__(self, data_dirs, feature_subset, my_ip_l, metrics, config):

        self.data_dirs = data_dirs
        self.feature_subset = feature_subset
        self.my_ip_l = my_ip_l
        self.metrics = metrics
        self.config = config

    def union_packets_df(self, list_of_files):

        t1 = time.time()

        packets_data_list = []
        idx = 1
        total = len(list_of_files)
        for file_tuple in list_of_files:
            csv_file = file_tuple[0]
            print(f'Extracting packets for file # {idx} of {total}')
            df_net = pd.read_csv(csv_file)
            if df_net['ip.proto'].dtype == object:
                df_net = df_net[df_net['ip.proto'].str.contains(',') == False]
            df_net = df_net[~df_net['ip.proto'].isna()]
            df_net['ip.proto'] = df_net['ip.proto'].astype(int)

            # calculates the ip_addr with the highest sum of 'udp.length' for each unique source IP
            ip_addr = df_net.groupby('ip.src').agg({'udp.length': sum}).reset_index(
            ).sort_values(by='udp.length', ascending=False).head(1)['ip.src'].iloc[0]
            if ip_addr in self.my_ip_l:  # if ip_addr is in my ip list, choose the ip with the 2nd highest udp length sum
                ip_addr = df_net.groupby('ip.src').agg({'udp.length': sum}).reset_index(
                ).sort_values(by='udp.length', ascending=False).head(2)['ip.src'].iloc[1]

            print('src ip:', ip_addr)
            # filters the DataFrame to retain only rows: 'ip.proto' is equal to 17, 'ip.src' is equal to ip_addr
            df_net = df_net[(df_net['ip.proto'] == 17) & (df_net['ip.src'] == ip_addr)]
            packets_data_list.append(df_net)

        dur = round(time.time() - t1, 2)
        print(f'\npackets extraction took {dur} seconds.\n')
        print('\nConcat all data frames into single data frame...\n')
        X = pd.concat(packets_data_list, axis=0)
        X = X.dropna()
        # X.to_csv(f'outputTrain.csv', index=False)
        print(f'\nUnion data frame shape: {X.shape}\n')

        return X


    def union_df(self, list_of_files):

        feature_extractor = FeatureExtractor(self.feature_subset, self.config)
        print(
            f'\nExtracting features...\nFeature Subset: {" ".join(self.feature_subset)}\nMetrics: {" ".join(self.metrics)}\n')

        t1 = time.time()

        train_data = []
        idx = 1
        total = len(list_of_files)
        for file_tuple in list_of_files:
            csv_file = file_tuple[0]
            print(f'Extracting features for file # {idx} of {total}')
            df_net = pd.read_csv(csv_file)
            if df_net['ip.proto'].dtype == object:
                df_net = df_net[df_net['ip.proto'].str.contains(',') == False]
            df_net = df_net[~df_net['ip.proto'].isna()]
            df_net['ip.proto'] = df_net['ip.proto'].astype(int)

            # calculates the ip_addr with the highest sum of 'udp.length' for each unique source IP
            ip_addr = df_net.groupby('ip.src').agg({'udp.length': sum}).reset_index(
            ).sort_values(by='udp.length', ascending=False).head(1)['ip.src'].iloc[0]
            if ip_addr in self.my_ip_l:  # if ip_addr is in my ip list, choose the ip with the 2nd highest udp length sum
                ip_addr = df_net.groupby('ip.src').agg({'udp.length': sum}).reset_index(
                ).sort_values(by='udp.length', ascending=False).head(2)['ip.src'].iloc[1]

            print('src ip:', ip_addr)
            # filters the DataFrame to retain only rows: 'ip.proto' is equal to 17, 'ip.src' is equal to ip_addr
            df_net = df_net[(df_net['ip.proto'] == 17) & (df_net['ip.src'] == ip_addr)]

            # if self.metric != 'bps':
            df_net = df_net[df_net['udp.length'] > 306]
            df_net = df_net.rename(columns={
                'udp.length': 'length', 'frame.time_epoch': 'time', 'frame.time_relative': 'time_normed'})
            df_net = df_net.sort_values(by=['time_normed'])
            df_net = df_net[['length', 'time', 'time_normed']]
            df_netml = feature_extractor.extract_features(df_net=df_net)

            # heuristic features
            # heuristic_model = IP_UDP_Heuristic(self.metric, self.config)
            # df_heuristic = heuristic_model.estimate(file_tuple)
            # df_netml = pd.merge(df_netml, df_heuristic, on='et')

            if len(file_tuple) <= 1 or len(df_net) == 0:
                idx += 1
                continue

            df_merged = df_netml
            for i, labels_file in enumerate(file_tuple):
                if i == 0:
                    continue    # advance pcap file
                df_labels = pd.read_csv(labels_file)
                df_merged = pd.merge(df_merged, df_labels, on='et')
                df_merged = df_merged.drop(df_merged.index[0])  # Drop the first row
                df_merged = df_merged.drop(df_merged.index[-1:])  # Drop the last  row

            # filter samples
            # fps filter
            if 'screenshots_num' in df_merged.columns:  # Discarding samples with less than 30 screenshots
                initial_count = len(df_merged)
                df_merged = df_merged[df_merged['screenshots_num'] >= 30]
                removed_count = initial_count - len(df_merged)
                print(f'File: Removed {removed_count} samples with screenshots_num < 30')
                df_merged = df_merged[df_merged.columns.difference(['screenshots_num'])]

            # if self.metric == 'brisque':
            #    df_merged['brisque'] = df_merged['brisque'].round().astype(int)

            # fname = os.path.basename(file_tuple[0])
            # df_merged.to_csv(f'output_df_{fname[:-4]}_{self.metric}.csv', index=False)
            train_data.append(df_merged)
            idx += 1

        dur = round(time.time() - t1, 2)
        print(f'\nFeature extraction took {dur} seconds.\n')
        print('\nConcat all session into single file...\n')
        X = pd.concat(train_data, axis=0)
        X = X.dropna()
        # X.to_csv(f'outputTrain.csv', index=False)
        print(f'\nUnion data frame shape: {X.shape}\n')
        # y = X[self.metric]
        X = X[X.columns.difference(['et', 'ts', 'file', 't_et', 'screenshots_num'])]
        # self.feature_matrix = X.copy()
        # self.target_vals = y.copy()
        #if self.metric == 'fps' or self.metric == 'brisque':
            #y = y.apply(lambda x: round(x))
        X['fps'].apply(lambda x: round(x))
        X['brisque'].apply(lambda x: round(x))


        return X

    def create_file_tuples_list(self, main_folder, metrics):
        tuples_list = []

        # Iterate over all folders in the main folder
        for folder_name in os.listdir(main_folder):
            folder_path = os.path.join(main_folder, folder_name)

            # Check if the item is a directory
            if os.path.isdir(folder_path):
                # Find the pcap file (starting with 'pcap' and ending with '.csv')
                pcap_file = next((f for f in os.listdir(folder_path) if f.startswith('pcap') and f.endswith('.csv')),
                                 None)

                # Find the labels files (starting with 'metric' and ending with '.csv')
                files_list = []
                for metric in metrics:
                    files_list.append(next((f for f in os.listdir(folder_path) if f.startswith(metric)
                                        and f.endswith('.csv')), None))

                # Add the tuple of paths to the list
                if pcap_file and len(files_list) > 0:
                    files_list.insert(0, pcap_file)
                    tuples_list.append(tuple(os.path.join(folder_path, file) for file in files_list))

        return tuples_list


    def histogram_density_plot(self, df):
        # Plot histogram and density function of packets length by 'udp.length'
        plt.figure(figsize=(12, 6))

        plt.subplot(1, 2, 1)
        sns.histplot(df['udp.length'], bins=10, kde=False)
        plt.title('Histogram of UDP Lengths')
        plt.xlabel('UDP Length')
        plt.ylabel('Frequency')

        plt.subplot(1, 2, 2)
        sns.kdeplot(df['udp.length'], shade=True)
        plt.title('Density Plot of UDP Lengths')
        plt.xlabel('UDP Length')
        plt.ylabel('Density')

        plt.tight_layout()
        plt.show()

if __name__ == '__main__':

    metrics = ['brisque', 'fps']
    estimation_method = 'ip-udp-ml'
    feature_subset = ['LSTATS', 'TSTATS']
    data_dirs = ["C:\\final_project\git_repo\data_collection\\falls"]
    # data_dirs = ["C:\\final_project\git_repo\data_collection\\falls"]
    my_ip_l = ['10.100.102.32', '192.168.0.102', '10.0.0.115']
    data_analyzer = DataAnalyzer(data_dirs, feature_subset, my_ip_l, metrics, config=project_config)
    # train
    file_tuples_list = []
    for dir in data_dirs:
        file_tuples_list += data_analyzer.create_file_tuples_list(dir, metrics)

    # union packets data frame
    union_packets_df = data_analyzer.union_packets_df(file_tuples_list)
    data_analyzer.histogram_density_plot(union_packets_df)

    # union features data frame
    union_df = data_analyzer.union_df(file_tuples_list)
    correlation_matrix = union_df.corr().abs()

    # Create heatmap
    plt.figure(figsize=(15, 12))
    sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt=".2f")
    plt.title('Correlation Heatmap')
    plt.show()

    print("\n(:\n")
