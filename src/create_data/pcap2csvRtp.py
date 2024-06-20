import os
import pandas as pd

def convert(x):
    #tshark_path = "C:\\Program Files\\Wireshark\\"
    for t in os.listdir(x):
        if t.endswith('.pcap'):
            output_csv = f"{x}/{t[:-5]}.csv"
            print(f'convert: {t} -> {t[:-5]}Rtp.csv')
            tshark_cmd = f"""
            tshark -r {x}/{t} -d udp.port==1024-49152,rtp -t e -T fields \
            -e frame.time_relative -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto \
            -e ip.len -e udp.srcport -e udp.dstport -e udp.length -e rtp.ssrc -e rtp.timestamp \
            -e rtp.seq -e rtp.p_type -e rtp.marker -E separator=, -E header=y > {x}/{t[:-5]}Rtp.csv
            """
            os.system(tshark_cmd)
            print(f"{t[:-5]}.csv was created successfully")

            # Add packet number column
            #print(f'Adding packet number column to: {output_csv}')
            #df = pd.read_csv(output_csv)
            #df.insert(0, 'packet_number', range(0, len(df)))
            #df.to_csv(output_csv, index=False)
            #print(f"Packet number column added to {output_csv}")

if __name__ == "__main__":
    #pcap_dir_path = "C:\\final_project\git_repo\data_collection\\falls\\2024_05_05_16_47_250bwFalls50KBps"
    #convert(pcap_dir_path)
    father_dir = "C:\\final_project\git_repo\data_collection\\bandwidth"

    for f in os.listdir(father_dir):
        convert("C:\\final_project\git_repo\data_collection\\bandwidth"+f'\{f}')