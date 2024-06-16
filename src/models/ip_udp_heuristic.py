import numpy as np
from collections import defaultdict
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
import pandas as pd
import time
import sys
from os.path import dirname, abspath
d = dirname(dirname(abspath(__file__)))
sys.path.append(d)
from util.helper_functions import read_net_file, filter_video_frames, is_freeze, get_freeze_dur


class IP_UDP_Heuristic:
    def __init__(self, metric, config):
        self.intra = 5  # max difference in packets sizes to considered packets with in same frame
        self.config = config
        self.metric = metric
        self.net_columns = ['frame.time_relative', 'frame.time_epoch', 'ip.src', 'ip.dst', 'ip.proto', 'ip.len',
                            'udp.srcport', 'udp.dstport', 'udp.length']
        self.max_lookback = 3  # lookback window for similar packet size
        self.my_ip = "192.168.0.105"    # update to your IP addr

    def assign(self, df):
        # assign frame number to each packet in df
        # return list of packets frame numbers
        l = self.max_lookback  # lookback window size for similar packet size
        frame_id_assignment = [-1 for _ in range(df.shape[0])]
        frame_id = 0
        for i in range(df.shape[0]):
            found = False
            s = df.iloc[i]['udp.length']
            for j in range(i-1, max(0, i-l-1), -1):  # looking in lookback window for packet with in same frame
                if abs(df.iloc[j]['udp.length'] - s) <= self.intra:
                    frame_id_assignment[i] = frame_id
                    found = True
                    break
            if not found:
                frame_id += 1
                frame_id_assignment[i] = frame_id
        return frame_id_assignment

    def estimate(self, file_tuple):
        csv_file = file_tuple[0]         # csv pcap file name
        #labels_file = file_tuple[1]
        df = pd.read_csv(csv_file)       # data frame of pcap file
        df = df[~df['ip.proto'].isna()]  # selects only the rows where 'ip.proto' is not NaN.
        df['ip.proto'] = df['ip.proto'].astype(str)         # converts the 'ip.proto' column to string type
        df = df[df['ip.proto'].str.contains(',') == False]  # remove entries with multiple protocol values separated by commas
        df['ip.proto'] = df['ip.proto'].apply(lambda x: int(float(x)))  # converts the values in the 'ip.proto' column from string to float, then from float to integer.

        #ip_addr = df.groupby('ip.dst').agg({'udp.length': sum}).reset_index(
        #    ).sort_values(by='udp.length', ascending=False).head(1)['ip.dst'].iloc[0]  # calculates the ip_addr with the highest sum of 'udp.length' for each unique destination IP
        ip_addr = df.groupby('ip.src').agg({'udp.length': sum}).reset_index(
            ).sort_values(by='udp.length', ascending=False).head(1)['ip.src'].iloc[0]  # calculates the ip_addr with the highest sum of 'udp.length' for each unique source IP
        if ip_addr == self.my_ip:   # if ip_addr is my ip, choose the ip with the 2nd highest udp length sum
            ip_addr = df.groupby('ip.src').agg({'udp.length': sum}).reset_index(
            ).sort_values(by='udp.length', ascending=False).head(2)['ip.src'].iloc[1]

        df = df[(df['ip.proto'] == 17) & (df['ip.src'] == ip_addr)]  # filter to retain only rows which 'ip.src' == ip_addr and 'ip.proto' == 17 (UDP protocol)
        df = df[(df['udp.length'] > 306)]   # filter by packet size
        df = df.sort_values(by=['frame.time_relative'])  # sorts df by 'time_relative' column in ascending order
        frame_id_assignment = self.assign(df)  # assign frame number to each packet, return list of packets frame nums
        df["frame_num"] = frame_id_assignment
        #df['udp.length'] = df['udp.length'] - 12  # rtp headers, not relevant in WhatsApp. other headers in whatsApp?
        df_grp_udp = df.groupby("frame_num").agg(
            {"frame.time_epoch": list, "udp.length": list}).reset_index()  # groups df by 'frame_num' and gather (agg) the 'frame.time_epoch' and 'udp.length' columns into lists
        df_grp_udp["frame_st"] = df_grp_udp["frame.time_epoch"].apply(
            lambda x: min(x))  # frame start time: the minimum frame time 'frame_st' for each frame.
        df_grp_udp["frame_et"] = df_grp_udp["frame.time_epoch"].apply(
            lambda x: max(x))  # frame end time: the maximum frame time 'frame_et' for each frame.
        df_grp_udp["frame_size"] = df_grp_udp["udp.length"].apply(
            lambda x: sum(x))  # frame size: calculates by summing udp.length of all packets in the frame.
        df_grp_udp["ft_end"] = df_grp_udp['frame_et'].apply(lambda x: int(x)+1)  # groups by seconds: calculates by adding 1 to the floor maximum frame time.

        df_grp_udp["frame_dur"] = df_grp_udp["frame_et"].diff()  # frame duration: calculates by taking the difference between consecutive frames end time
        df_grp_udp["avg_frame_dur"] = df_grp_udp["frame_dur"].rolling(
            30).mean()  # rolling average frame duration: calculates over a window of 30 frames.
        df_grp_udp = df_grp_udp.fillna(0)  # fills any missing values (NaNs) in df_grp_udp with 0.
        idx = df_grp_udp.index[df_grp_udp['frame_dur'] >= 8].tolist()  # create list of frames with 'frame_dur' >= 8
        if len(idx) > 0:
            idx = idx[0]+1  # index of first frame with 'frame_dur' >= 8 if there is such frame
        else:
            idx = 0
        df_grp_udp = df_grp_udp.iloc[idx:]  # selects the rows from idx onwards
        # freeze calculation
        df_grp_udp["is_freeze"] = df_grp_udp.apply(is_freeze, axis=1)  # calculates whether each frame represents a freeze event
        df_grp_udp["freeze_dur"] = df_grp_udp.apply(get_freeze_dur, axis=1)  # calculates freeze duration

        # group by seconds, for each second calculates frames count, total frames size, total freeze frames,
        # total freeze duration, frame duration std
        df_grp_udp = df_grp_udp.groupby("ft_end").agg({"frame_size": ["count", "sum"], "is_freeze": "sum",
                                                       "freeze_dur": "sum",
                                                       "frame_dur": "std"}).reset_index()

        # rename columns
        df_grp_udp.columns = ['_'.join(col).strip('_')
                              for col in df_grp_udp.columns.values]
        df_grp_udp = df_grp_udp.rename(columns={'frame_size_count': 'predicted_framesReceivedPerSecond',
                                                'is_freeze_sum': 'freeze_count',
                                                'frame_size_sum': 'predicted_bitrate',
                                                'freeze_dur_sum': 'freeze_dur',
                                                'frame_dur_std': 'predicted_frame_jitter',
                                                'ft_end': 'et'
                                                })
        df_grp_udp['predicted_bitrate'] = df_grp_udp['predicted_bitrate']*8  # converts bytes to bits
        df_grp_udp['predicted_frame_jitter'] *= 1000  # converts second to ms

        #col = "ft_end"
        #metric_col = f'{self.metric}_ip-udp-heuristic'
        #webrtc_col = f'{self.metric}_gt'
        #df_merge = df_merge.rename(columns={
        #                           f'predicted_{self.metric}': metric_col, self.metric: webrtc_col, 'ts': 'timestamp'})

        #df_grp_udp['file'] = csv_file  # add pcap csv file name col

        #df_merge = df_merge[[webrtc_col, metric_col,
        #                     'timestamp', 'file', 'dataset']]
        #df_merge = df_merge.dropna()
        #if df_merge.shape[0] == 0:
        #    return None
        #if self.metric == 'framesReceivedPerSecond':
        #    df_merge[webrtc_col] = df_merge[webrtc_col].apply(
        #        lambda x: round(x))

        return df_grp_udp
