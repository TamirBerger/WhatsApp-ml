import subprocess


framerate = 1
timeout = 60
ffmpeg_path = r'C:\final_project\ffmpeg.exe'


def capture_screen(output_folder, num_frames, framerate):
    print("begin with screen captures...")
    capture_command = f'{ffmpeg_path} -f gdigrab -framerate {framerate} -i desktop -q:v 0 -frames {num_frames} {output_folder}\\output_%03d.png'
    process = subprocess.Popen(capture_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()

    if process.returncode == 0:
        print("Screen capture completed successfully.")
    else:
        print(f"Error during screen capture:\n{err.decode()}")


if __name__ == "__main__":
    # Choose the folder for capturing images
    capture_folder = "C:\\final_project\screen_captures"

    # Run screen capture command
    capture_screen(capture_folder, str(timeout * framerate), str(framerate))
