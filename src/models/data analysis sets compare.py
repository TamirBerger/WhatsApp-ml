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
from util.helper_functions import filter_ptype


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
            idx += 1

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

            if len(file_tuple) <= 1 or len(df_net) == 0:
                idx += 1
                continue

            df_merged = df_netml
            for i, labels_file in enumerate(file_tuple):
                if i == 0:
                    continue    # advance pcap file

                df_labels = pd.read_csv(labels_file)
                if labels_file.endswith('brisque_piqeLabels.csv'):
                    df_labels = df_labels[df_labels.columns.difference(['brisque'])]

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

            # add quality metric from brisque score
            df_merged['quality'] = np.select([(df_merged['brisque'] < 20),
                                              (df_merged['brisque'] >= 20) & (df_merged['brisque'] < 40),
                                              (df_merged['brisque'] >= 40) & (df_merged['brisque'] < 60),
                                              (df_merged['brisque'] >= 60) & (df_merged['brisque'] < 80)],
                                             [1, 2, 3, 4], default=5)

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

    def union_packets_df_rtp(self, list_of_files):
        t1 = time.time()

        packets_data_list = []
        idx = 1
        total = len(list_of_files)

        for file_tuple in list_of_files:
            csv_file = file_tuple[0]
            print(f'Extracting features for file # {idx} of {total}')

            df_net = pd.read_csv(csv_file)

            # clean ip.proto column
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
            # filters the DataFrame to retain only rows: 'ip.proto' is equal to 17, 'ip.src' is equal to ip_addr,
            #                                            'trp.ssrc' is not na
            df_net = df_net[(df_net['ip.proto'] == 17) & (df_net['ip.src'] == ip_addr) & (~pd.isna(df_net["rtp.ssrc"]))]
            df_net['rtp.p_type'] = df_net['rtp.p_type'].apply(filter_ptype)
            df_net['rtp.p_type'] = df_net['rtp.p_type'].dropna()

            packets_data_list.append(df_net)
            idx += 1

        dur = round(time.time() - t1, 2)
        print(f'\nrtp packets extraction took {dur} seconds.\n')
        print('\nConcat all data frames into single data frame...\n')
        X = pd.concat(packets_data_list, axis=0)
        X = X.dropna()
        # X.to_csv(f'outputTrain.csv', index=False)
        print(f'\nUnion data frame shape: {X.shape}\n')

        return X

    def union_df_rtp(self, list_of_files):
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

            # clean ip.proto column
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
            # filters the DataFrame to retain only rows: 'ip.proto' is equal to 17, 'ip.src' is equal to ip_addr,
            #                                            'trp.ssrc' is not na
            df_net = df_net[(df_net['ip.proto'] == 17) & (df_net['ip.src'] == ip_addr) & (~pd.isna(df_net["rtp.ssrc"]))]
            df_net['rtp.p_type'] = df_net['rtp.p_type'].apply(filter_ptype)
            df_net['rtp.p_type'] = df_net['rtp.p_type'].dropna()

            # filter by rtp type of video used by WhatsApp, or rtx type and packet size > 306
            df_net = df_net[(df_net['rtp.p_type'].isin(self.config['video_ptype'])) |
                            ((df_net['rtp.p_type'].isin(self.config['rtx_ptype'])) & (df_net['udp.length'] > 306))]

            # rename headers, keep only 'length', 'time', 'time_normed',
            # 'rtp.timestamp', 'rtp.seq', 'rtp.marker', 'rtp.p_type' columns
            df_net = df_net.rename(
                columns={'udp.length': 'length', 'frame.time_epoch': 'time', 'frame.time_relative': 'time_normed'})
            df_net = df_net.sort_values(by=['time_normed'])
            df_net = df_net[['length', 'time', 'time_normed', 'rtp.timestamp', 'rtp.seq', 'rtp.marker', 'rtp.p_type']]
            df_netml = feature_extractor.extract_features(df_net=df_net)
            df_rtp = feature_extractor.extract_rtp_features(df_net=df_net)
            df = pd.merge(df_netml, df_rtp, on='et')

            if len(file_tuple) <= 1 or len(df_net) == 0:
                idx += 1
                continue

            df_merged = df
            for i, labels_file in enumerate(file_tuple):
                if i == 0:
                    continue  # advance pcap file
                df_labels = pd.read_csv(labels_file)
                df_merged = pd.merge(df_merged, df_labels, on='et')

            df_merged = df_merged.drop(df_merged.index[0])  # Drop the first row
            df_merged = df_merged.drop(df_merged.index[-1:])  # Drop the last  row

            # filter samples
            if 'screenshots_num' in df_merged.columns:  # Discarding samples with less than 45 screenshots
                initial_count = len(df_merged)
                df_merged = df_merged[df_merged['screenshots_num'] >= 30]
                removed_count = initial_count - len(df_merged)
                print(f'File: Removed {removed_count} samples with screenshots_num < 30')
                df_merged = df_merged[df_merged.columns.difference(['screenshots_num'])]

            # if self.metric == 'brisque':
            #    df_merged['brisque'] = df_merged['brisque'].round().astype(int)

            fname = os.path.basename(file_tuple[0])
            # df_merged.to_csv(f'output_df_{fname[:-4]}_{self.metric}.csv', index=False)
            train_data.append(df_merged)
            idx += 1

        dur = round(time.time() - t1, 2)
        print(f'\nFeature extraction took {dur} seconds.\n')
        print("\nConcat all session into single file...\n")
        X = pd.concat(train_data, axis=0)
        X = X.dropna()
        # X.to_csv(f'outputTrain.csv', index=False)
        print(f'\nUnion data frame shape: {X.shape}\n')
        X = X[X.columns.difference(['et', 'ts', 'file', 't_et', 'screenshots_num', 'n_pkt_diff_mean',
                        'n_pkt_diff_std', 'n_pkt_diff_min', 'n_pkt_diff_max', 'n_pkt_diff_q1',
                        'n_pkt_diff_q2', 'n_pkt_diff_q3'])]
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
                pcap_file = next((f for f in os.listdir(folder_path) if f.startswith('pcap') and f.endswith('Rtp.csv')),
                                 None)

                # Find the labels files (starting with 'metric' and ending with '.csv')
                files_list = []
                for metric in metrics:
                    if metric == 'piqe':
                        metric = 'brisque_piqe'

                    files_list.append(next((f for f in os.listdir(folder_path) if f.startswith(metric)
                                        and f.endswith('.csv')), None))

                # Add the tuple of paths to the list
                if pcap_file and len(files_list) > 0:
                    files_list.insert(0, pcap_file)
                    tuples_list.append(tuple(os.path.join(folder_path, file) for file in files_list))

        return tuples_list

    def histogram_density_plot(self, df_list, names_list, header):
        plt.figure(figsize=(18, 6))

        colors = sns.color_palette("husl", len(df_list))  # Generate a list of colors

        # Histogram
        plt.subplot(1, 3, 1)
        for df, name, color in zip(df_list, names_list, colors):
            sns.histplot(df[header], bins=10, kde=False, color=color, label=name)
        plt.title(f'Histogram of {header}')
        plt.xlabel(header)
        plt.ylabel('Frequency')
        plt.legend()

        # Density Plot
        plt.subplot(1, 3, 2)
        for df, name, color in zip(df_list, names_list, colors):
            sns.kdeplot(df[header], shade=True, color=color, label=name)
        plt.title(f'Density Plot of {header}')
        plt.xlabel(header)
        plt.ylabel('Density')
        plt.legend()

        # CDF Plot
        plt.subplot(1, 3, 3)
        for df, name, color in zip(df_list, names_list, colors):
            sns.ecdfplot(df[header], color=color, label=name)
        plt.title(f'CDF Plot of {header}')
        plt.xlabel(header)
        plt.ylabel('CDF')
        plt.legend()

        # Annotate the y-axis with the y-values at the steps for the 'quality' header in the CDF plot
        if header == 'quality':
            sorted_data = [df[header].sort_values().values for df in df_list]
            n_values = [len(data) for data in sorted_data]
            y_values_list = []
            for data, n in zip(sorted_data, n_values):
                y_values = []
                for i, val in enumerate(data):
                    y = (i + 1) / n
                    if i == 0 or data[i] != data[i - 1]:  # Only annotate at steps
                        y_values.append(y)
                y_values_list.append(y_values)

            plt.subplot(1, 3, 3)
            for y_values, color in zip(y_values_list, colors):
                plt.gca().set_yticks(y_values)
                plt.gca().set_yticklabels([f'{y:.2f}' for y in y_values], color=color)

        plt.tight_layout()
        plt.savefig(f'C:\\final_project\\notes and docs\\histogram_density_CDF_{header}.png')
        plt.close()

    def rtp_classifier(self, df):
        # Group data by 'rtp.p_type' and calculate statistics for 'udp.length'
        stats = df.groupby('rtp.p_type')['udp.length'].describe().reset_index()

        # Save statistics to a CSV file
        stats.to_csv('C:\\final_project\\notes and docs\\udp_length_statistics.csv', index=False)

        # Create histograms, density plots, and CDF plots for each unique 'rtp.p_type'
        unique_p_types = df['rtp.p_type'].unique()

        for p_type in unique_p_types:
            subset = df[df['rtp.p_type'] == p_type]

            plt.figure(figsize=(12, 6))

            plt.subplot(1, 3, 1)
            sns.histplot(subset['udp.length'], bins=30, kde=False)
            plt.title(f'Histogram of UDP Lengths for RTP Payload Type {int(p_type)}')
            plt.xlabel('UDP Length')
            plt.ylabel('Frequency')

            plt.subplot(1, 3, 2)
            sns.kdeplot(subset['udp.length'], shade=True)
            plt.title(f'Density Plot of UDP Lengths for RTP Payload Type {int(p_type)}')
            plt.xlabel('UDP Length')
            plt.ylabel('Density')

            plt.subplot(1, 3, 3)
            sns.ecdfplot(subset['udp.length'])
            plt.title(f'CDF Plot of UDP Lengths for RTP Payload Type {int(p_type)}')
            plt.xlabel('UDP Length')
            plt.ylabel('CDF')

            plt.tight_layout()
            plt.savefig(f'C:\\final_project\\notes and docs\\udp_length_plots_p_type_{int(p_type)}.png')
            plt.close()

        # Create combined plots
        plt.figure(figsize=(18, 6))

        plt.subplot(1, 3, 1)
        for p_type in unique_p_types:
            subset = df[df['rtp.p_type'] == p_type]
            sns.histplot(subset['udp.length'], bins=30, kde=False, label=f'P Type {int(p_type)}', alpha=0.5)
        plt.title('Combined Histogram of UDP Lengths for All RTP Payload Types')
        plt.xlabel('UDP Length')
        plt.ylabel('Frequency')
        plt.legend()

        plt.subplot(1, 3, 2)
        for p_type in unique_p_types:
            subset = df[df['rtp.p_type'] == p_type]
            sns.kdeplot(subset['udp.length'], shade=True, label=f'P Type {int(p_type)}', alpha=0.5)
        plt.title('Combined Density Plot of UDP Lengths for All RTP Payload Types')
        plt.xlabel('UDP Length')
        plt.ylabel('Density')
        plt.legend()

        plt.subplot(1, 3, 3)
        for p_type in unique_p_types:
            subset = df[df['rtp.p_type'] == p_type]
            sns.ecdfplot(subset['udp.length'], label=f'P Type {int(p_type)}')
        plt.title('Combined CDF Plot of UDP Lengths for All RTP Payload Types')
        plt.xlabel('UDP Length')
        plt.ylabel('CDF')
        plt.legend()

        plt.tight_layout()
        plt.savefig('C:\\final_project\\notes and docs\\udp_length_combined_plots.png')
        plt.close()

        # Show statistics
        print(stats)


if __name__ == '__main__':

    metrics = ['brisque', 'fps', 'piqe']
    estimation_method = 'ip-udp-ml'
    feature_subset = ['LSTATS', 'TSTATS']
    data_dirs = [#"C:\\final_project\git_repo\data_collection\\falls",
                 #"C:\\final_project\git_repo\data_collection\\bandwidth",
                 "C:\\final_project\git_repo\data_collection\\loss-0",
                 "C:\\final_project\git_repo\data_collection\\loss-1",
                 "C:\\final_project\git_repo\data_collection\\loss-2",
                 "C:\\final_project\git_repo\data_collection\\loss-5",
                 "C:\\final_project\git_repo\data_collection\\loss-10"
                 ]
    my_ip_l = ['10.100.102.32', '192.168.0.102', '10.0.0.115', '192.168.0.100', '192.168.0.103', '192.168.0.104']
    data_analyzer = DataAnalyzer(data_dirs, feature_subset, my_ip_l, metrics, config=project_config)
    # train
    file_tuples_list = []
    df_list = []
    name_list = []
    for i, dir in enumerate(data_dirs):
        file_tuples_list = data_analyzer.create_file_tuples_list(dir, metrics)
        df_list.append(data_analyzer.union_df(file_tuples_list))
        name_list.append(os.path.basename(dir))

    # union packets data frame
    #union_packets_df = data_analyzer.union_packets_df(file_tuples_list)
    #data_analyzer.histogram_density_plot(union_packets_df, 'udp.length')

    # union traffic features and QoE metrics data frame


    data_analyzer.histogram_density_plot(df_list, name_list, 'piqe')
    data_analyzer.histogram_density_plot(df_list, name_list, 'fps')
    data_analyzer.histogram_density_plot(df_list, name_list, 'brisque')
    data_analyzer.histogram_density_plot(df_list, name_list, 'quality')
    data_analyzer.histogram_density_plot(df_list, name_list, 'l_num_bytes')
    data_analyzer.histogram_density_plot(df_list, name_list, 'l_num_pkts')
    data_analyzer.histogram_density_plot(df_list, name_list, 'l_mean')



    # correlation matrix
    #correlation_matrix = union_df.corr().abs()
    #plt.figure(figsize=(10, 8))
    #sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt='.2f', linewidths=0.5)
    #plt.title('Correlation Matrix')
    #plt.show()

    # union traffic features and QoE metrics data frame RTP
    #union_df_rtp = data_analyzer.union_df_rtp(file_tuples_list)
    #data_analyzer.histogram_density_plot(union_df_rtp, 'brisque')
    #correlation_matrix_rtp = union_df_rtp.corr().abs()

    # Get correlations for 'fps' and 'brisque'
    #correlation_fps = correlation_matrix_rtp['fps'].sort_values(ascending=False)
    #correlation_brisque = correlation_matrix_rtp['brisque'].sort_values(ascending=False)

    # Exclude self-correlation
    #correlation_fps = correlation_fps[correlation_fps.index != 'fps']
    #correlation_brisque = correlation_brisque[correlation_brisque.index != 'brisque']

    # Print results
    #print("Correlations with 'fps':")
    #print(correlation_fps)

    #print("\nCorrelations with 'brisque':")
    #print(correlation_brisque)

    # union packets data frame
    #union_packets_df_rtp = data_analyzer.union_packets_df_rtp(file_tuples_list)
    #union_packets_df_rtp.to_csv('C:\\final_project\\notes and docs\\union_packets_rtp.csv', index=False)
    #data_analyzer.rtp_classifier(union_packets_df_rtp)

    print("\n(:\n")
