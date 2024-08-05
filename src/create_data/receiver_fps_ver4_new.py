import cv2
import numpy as np
import time
import mss
import datetime
import csv
import sys


class FPScalculator:
    def __init__(self, duration=10):
        self.unique_frames_per_second = []
        self.x, self.y, self.width, self.height = 680, 70, 560, 1000  # fps validation coordinates
        self.start_time = None  # update at beginning of 'run' method
        self.grabs = []
        self.fps_list = []  # list of lists[2]: [end time, number of frames received in the window]
        self.duration = duration
        self.screenshots_list = []
        self.identical_pixels_list = []  # List to store identical pixel counts for each second
        self.total_pixels_compared = self.width * self.height  # Total number of pixels to compare
        self.identical_pixels_sums = []  # List to store sum of identical pixels between successive unique frames

    def run(self):
        self.start_time = time.time()
        prev_time = int(self.start_time)
        prev_len = 0
        while True:
            with mss.mss() as sct:
                monitor = {"top": self.y, "left": self.x, "width": self.width, "height": self.height}
                screenshot = np.array(sct.grab(monitor))
            self.grabs.append((int(time.time()) + 1, screenshot))  # (et - end time of window, screenshot)

            if int(time.time()) - prev_time >= 1.0:
                self.screenshots_list.append((int(time.time()), len(self.grabs) - prev_len))
                prev_time = int(time.time())
                prev_len = len(self.grabs)

            if time.time() - self.start_time >= self.duration:
                print(f'FPS: overall screen shots: {len(self.grabs)}, during {self.duration} seconds')
                break

    def calculate_identical_pixels(self, frame1, frame2):
        identical_pixels = np.sum(frame1 == frame2)
        return identical_pixels

    def calculate_fps(self):
        for (end_time_stamp, image) in self.grabs:
            #frame = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
            #gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray_frame = image

            if len(self.unique_frames_per_second) == 0 or not np.array_equal(gray_frame, self.unique_frames_per_second[-1][1]):
                if len(self.unique_frames_per_second) != 0:
                    print(self.unique_frames_per_second[-1][1])
                    print(gray_frame)
                    print()
                self.unique_frames_per_second.append((end_time_stamp, gray_frame))


        print(f'FPS: total unique frames captured: {len(self.unique_frames_per_second)}')

        first_end_time_step = self.unique_frames_per_second[0][0]
        for i in range(self.duration + 1):
            self.fps_list = [[first_end_time_step + i, 0] for i in range(self.duration + 1)]

        for i, (end_time_stamp, _) in enumerate(self.unique_frames_per_second):
            self.fps_list[end_time_stamp - first_end_time_step][1] += 1

        for i, (et, fps) in enumerate(self.fps_list):
            print(f'sec: {i}, end epoch_time: {et}: {fps} FPS')

        fps_values = [t[1] for t in self.fps_list]

        avg = np.array(fps_values[1:self.duration]).mean()
        print(f'\naverage fps for {self.duration} seconds: {avg}')

        std = np.array(fps_values[1:self.duration]).std()
        print(f'standard deviation: {std}')

        # Calculate identical pixels between successive unique frames
        for i in range(1, len(self.unique_frames_per_second)):
            prev_frame = self.unique_frames_per_second[i - 1][1]
            curr_frame = self.unique_frames_per_second[i][1]
            identical_pixels = self.calculate_identical_pixels(prev_frame, curr_frame)
            self.identical_pixels_sums.append(identical_pixels)

            # Store the sum of identical pixels in relation to the time slots
            self.identical_pixels_list.append((self.unique_frames_per_second[i][0], identical_pixels))

        # Print the sum of identical pixels for each time slot
        for et, identical_pixels in self.identical_pixels_list:
            print(f'end time: {et}, identical pixels with previous frame: {identical_pixels} out of {self.total_pixels_compared}')

        # Print the sum of identical pixels for all successive unique frames
        print(f'\nSum of identical pixels between each pair of successive unique frames: {self.identical_pixels_sums}')

    def display_unique_frames_captured(self):
        print(f'total unique frames captured: {len(self.unique_frames_per_second)}')
        for (_, unique_frame) in self.unique_frames_per_second:
            cv2.imshow('Frame', unique_frame)
            cv2.waitKey(0)
            cv2.destroyAllWindows()

    def display_all_grabs(self):
        print(f'total screen shots captured: {len(self.grabs)}')
        for (_, image) in self.grabs:
            cv2.imshow('Frame', image)
            cv2.waitKey(0)
            cv2.destroyAllWindows()


def write_to_csv(fps_list, screenshots_num_l, identical_pixels_list, total_pixels_compared, identical_pixels_sums, dir_path):
    filename = dir_path + "\\fpsLabels.csv"
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['fps', 'et', 'screenshots_num', 'identical_pixels', 'total_pixels_compared']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for (et, fps), (_, screenshots_num), (_, identical_pixels) in zip(fps_list, screenshots_num_l, identical_pixels_list):
            writer.writerow({'fps': fps, 'et': et, 'screenshots_num': screenshots_num, 'identical_pixels': identical_pixels, 'total_pixels_compared': total_pixels_compared})

    print("\nfps labels csv file was created")

    filename = dir_path + "\\identicalPixelsSums.csv"
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['identical_pixels_sum']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for identical_pixels_sum in identical_pixels_sums:
            writer.writerow({'identical_pixels_sum': identical_pixels_sum})

    print("\nidentical pixels sums csv file was created")


def main():
    time.sleep(3)
    prog_start_time = time.time()

    if len(sys.argv) < 4:
        print("Usage: python create_pcap.py <arg1> <arg2>")
        return

    initial_time = sys.argv[1]
    BW = sys.argv[2]
    dir_path = sys.argv[3]
    duration = int(sys.argv[4])  # Duration of capture in seconds

    print(f'receiver fps ver4: start time: {prog_start_time}')

    fpsCalculator = FPScalculator(duration)
    fpsCalculator.run()
    print(f'receiver fps ver 4: total duration of captures part: {time.time() - prog_start_time}')

    time.sleep(5)
    fpsCalculator.calculate_fps()
    write_to_csv(fpsCalculator.fps_list, fpsCalculator.screenshots_list, fpsCalculator.identical_pixels_list, fpsCalculator.total_pixels_compared, fpsCalculator.identical_pixels_sums, dir_path)
    print(f'\ntotal duration of receiver fps program: {time.time() - prog_start_time}')
    fpsCalculator.display_unique_frames_captured()

if __name__ == "__main__":
    main()