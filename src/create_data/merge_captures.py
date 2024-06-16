import multiprocessing
import subprocess
import time


def run_file(filename):
    subprocess.call(['python', filename])


if __name__ == '__main__':
    time.sleep(5)  # 5 seconds to open full screen video window
    # List of file names to run
    files = ['create_pcap.py', 'screen_capture_ffmpeg.py']

    # Create a pool of processes
    pool = multiprocessing.Pool(processes=len(files))

    # Run the files in parallel
    print("start run captures files in parallel")
    pool.map(run_file, files)

    # Close the pool
    pool.close()
    pool.join()
