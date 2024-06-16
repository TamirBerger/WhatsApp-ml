import psutil
import time


def get_bandwidth_usage(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            pid = proc.info['pid']
            return pid
    return None


def monitor_bandwidth(process_name, duration):
    pid = get_bandwidth_usage(process_name)
    if pid is None:
        print("Process", process_name, "not found.")
        return

    start_time = time.time()
    end_time = start_time + duration
    bandwidth_data = []

    while time.time() < end_time:
        network_usage = psutil.net_io_counters(pernic=False, nowrap=True)
        for connection in psutil.net_connections(kind='inet'):
            if connection.pid == pid:
                bandwidth_data.append({
                    'timestamp': time.time(),
                    'upload': connection.bytes_sent,
                    'download': connection.bytes_recv
                })
        time.sleep(1)
        # elapsed_time = time.time() - start_time
        # sleep_duration = 1 - (elapsed_time % 1)  # Adjust sleep duration to maintain synchronization
        # time.sleep(sleep_duration)

    return bandwidth_data


# Example usage:
process_name = "chrome.exe"  # Replace with the name of the process you want to monitor
duration = 60  # Duration in seconds
bandwidth_info = monitor_bandwidth(process_name, duration)
if bandwidth_info:
    print("Bandwidth Usage for", process_name, "over", duration, "seconds:")
    for data in bandwidth_info:
        print("Timestamp:", data['timestamp'])
        print("Upload:", data['upload'], "bytes")
        print("Download:", data['download'], "bytes")
else:
    print("Process", process_name, "not found.")