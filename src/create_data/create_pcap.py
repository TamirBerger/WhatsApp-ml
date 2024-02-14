import os
import datetime

timeout = 60
initial_time = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")


def capture_and_save_pcap(output_path, interface):
    tshark_path = "C:\\Program Files\\Wireshark\\"
    duration = str(timeout)

    # Create a new pcap file
    tshark_cmd = f'"{tshark_path}tshark" -i {interface} -a duration:{duration} -w {output_path}\\pcap_{initial_time}.pcap'
    os.system(tshark_cmd)


if __name__ == "__main__":
    output_pcap_path = "C:\\final_project\pcap_files"
    wifi_interface = "\\Device\\NPF_{CB405C34-9E8D-4DDA-876E-D44BC4CA0E3F}"

    capture_and_save_pcap(output_pcap_path, wifi_interface)
