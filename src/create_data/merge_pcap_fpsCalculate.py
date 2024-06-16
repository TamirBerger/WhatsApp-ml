import multiprocessing
import subprocess
import time
import datetime
import os


def run_file(args):
    filename, *arguments = args
    subprocess.call(['python', filename, *arguments])


if __name__ == '__main__':
    time.sleep(5)  # 5 seconds to open full screen video window
    initial_time = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M")
    BW = "50"
    directory = f"C:\\final_project\pcap_files\\{initial_time}_{BW}KBps"
    duration = "122"
    if not os.path.exists(directory):
        os.makedirs(directory)

    files = [
        ('create_pcap.py', initial_time, BW, directory, duration),
        ('receiver_fps_ver4.py', initial_time, BW, directory, duration)
    ]

    # Create a pool of processes
    pool = multiprocessing.Pool(processes=len(files))

    # Run the files in parallel
    print("start run pcap and fps calculate files in parallel")
    pool.map(run_file, files)

    # Close the pool
    pool.close()
    pool.join()
