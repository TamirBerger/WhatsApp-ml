import sys
import os
from util.helper_functions import *
from util.config import project_config
from util.feature_extraction import FeatureExtractor
from os.path import dirname, abspath, basename
project_root = dirname(dirname(abspath(__file__)))
sys.path.append(project_root)


class Preprocessor:

    def __init__(self, feature_subset, my_ip):
        self.feature_subset = feature_subset
        self.config = project_config
        self.net_columns = ['frame.time_relative', 'frame.time_epoch', 'ip.src', 'ip.dst', 'ip.proto', 'ip.len',
                            'udp.srcport', 'udp.dstport', 'udp.length', 'brisque']
        self.my_ip = my_ip  # update to your IP addr

    def process_input(self, file_tuples):
        n = len(file_tuples)
        idx = 1
        feature_extractor = FeatureExtractor(
            self.feature_subset, self.config)
        for ftuple in file_tuples:
            # pcap_file = ftuple[0]
            csv_file = ftuple[0]
            # if os.path.exists(csv_file[:-4]+f'_rtp_ml_{self.vca}_{self.dataset}.csv'):
            #     print('Already exists')
            #     continue
            labels_file = ftuple[1]
            print(f'Extracting features for {idx} of {n}...')
            df_net = pd.read_csv(csv_file)
            if df_net is None or len(df_net) == 0:
                idx += 1
                continue
            df_net = df_net[~df_net['ip.proto'].isna()]  # selects only the rows where 'ip.proto' is not NaN.
            df_net['ip.proto'] = df_net['ip.proto'].astype(str)  # converts the 'ip.proto' column to string type
            df_net = df_net[df_net['ip.proto'].str.contains(',') == False]  # remove entries with multiple protocol values separated by commas, assuming each entry should have only one protocol.
            df_net['ip.proto'] = df_net['ip.proto'].apply(
                lambda x: int(float(x))) # converts the values in the 'ip.proto' column from string to float, then from float to integer.

            #ip_addr = df_net.groupby('ip.dst').agg({'udp.length': sum}).reset_index(
            #).sort_values(by='udp.length', ascending=False).head(1)['ip.dst'].iloc[0]  # calculates the IP address (ip_addr) with the highest sum of 'udp.length' for each unique destination IP address ('ip.dst')

            # calculates the ip_addr with the highest sum of 'udp.length' for each unique source IP
            ip_addr = df_net.groupby('ip.src').agg({'udp.length': sum}).reset_index(
            ).sort_values(by='udp.length', ascending=False).head(1)['ip.src'].iloc[0]
            if ip_addr == self.my_ip:  # if ip_addr is my ip, choose the ip with the 2nd highest udp length sum
                ip_addr = df.groupby('ip.src').agg({'udp.length': sum}).reset_index(
                ).sort_values(by='udp.length', ascending=False).head(2)['ip.src'].iloc[1]

            print('src ip:', ip_addr)
            # filters the DataFrame to retain only rows: 'ip.proto' is equal to 17, 'ip.src' is equal to ip_addr
            df_net = df_net[(df_net['ip.proto'] == 17) & (df_net['ip.src'] == ip_addr)]
            df_net = df_net[df_net['udp.length'] > 306]  # filters to retain only rows where the UDP length > 306
            df_net = df_net.rename(columns={  # rename columns
                                   'udp.length': 'length', 'frame.time_epoch': 'time', 'frame.time_relative': 'time_normed'})
            df_net = df_net.sort_values(by=['time_normed'])  # sorts df_net by 'time_normed' column in ascending order
            df_net['iat'] = df_net['time_normed'].diff().shift(-1)  # calculates the inter-arrival time ('iat') between consecutive packets, and shift the result upwards (to the packet before)

            # cutoff_time = df_net[df_net['iat'] > 3].sort_values(by='time_normed', ascending=False)
            # if cutoff_time.shape[0] > 0:
            #     cutoff_time = cutoff_time.iloc[0]['time_normed']
            #     df_net = df_net[df_net['time_normed'] > cutoff_time]

            if df_net.shape[0] == 0:
                idx += 1
                continue
            dst_df = df_net.groupby('ip.dst').agg({'length': sum}).reset_index(
            ).sort_values(by='length', ascending=False).head(1)['ip.dst']  # calculates the dst IP address (dst) with the highest sum of 'length' for each unique dst IP address ('ip.dst').
            if len(dst_df) == 0:
                idx += 1
                continue
            dst = dst_df.iloc[0]  # retrieves the dst IP address (dst) from the first row of dst_df.
            print('dst ip:', dst)

            df_net = df_net[df_net['ip.dst'] == dst]  # filters to retain only rows where ('ip.src') matches the src.
            print('ML', df_net.shape)
            df_netml = feature_extractor.extract_features(df_net=df_net)

            df_labels = pd.read_csv(labels_file)
            if df_labels is None or len(df_net) == 0:
                idx += 1
                continue

            feature_file = csv_file[:-4] + '_ml_WhatsApp.csv'
            print(feature_file)

            df_merged = pd.merge(df_netml, df_labels, on='et')
            df_merged = df_merged.drop(df_merged.index[0])    # Drop the first row
            df_merged = df_merged.drop(df_merged.index[-2:])  # Drop the last two rows

            df_merged.to_csv(feature_file, index=False)
            idx += 1

            '''

            df_net = read_net_file(csv_file)
            if df_net is None:
                idx += 1
                continue
            df_net = df_net[(df_net['udp.length'] > 306)]
            df_net = df_net.rename(columns={
                                   'udp.length': 'length', 'frame.time_epoch': 'time', 'frame.time_relative': 'time_normed'})
            df_net = df_net.sort_values(by=['time_normed'])
            src_df = df_net.groupby('ip.src').agg({'length': sum}).reset_index(
            ).sort_values(by='length', ascending=False).head(1)['ip.src']
            if len(src_df) == 0:
                idx += 1
                continue
            src = src_df.iloc[0]
            df_net = df_net[df_net['ip.src'] == src]

            print('RTP-ML', df_net.shape)
            df_netml = feature_extractor.extract_features(df_net=df_net)
            # df_labels = feature_extractor.extract_labels_features(df_net=df_net)
            # df = pd.merge(df_netml, df_labels, on='et')

            # print(df_merged.head(5)[
            #      ['framesReceivedPerSecond', 'bitrate', 'frame_jitter', 'et']])
            feature_file = csv_file[:-4] + '_rtp_ml_WhatsApp.csv'
            df_netml.to_csv(feature_file, index=False)
            
            '''