import cv2
import numpy as np
import time
import mss
import datetime
import csv
import sys
from PIL import Image
import pytesseract
import re


class BpsCalculator:
    def __init__(self, duration=10):
        # Define the region where WhatsApp Bps is displayed (replace these coordinates with your own)
        self.x, self.y, self.width, self.height = 2210, 920, 100, 27
        self.start_time = None  # update at the beginning of 'run' method
        self.grabs = []  # tuples list: (end time, image of kBps)
        self.Bps_list = []
        self.duration = duration

    def run(self):
        self.start_time = time.time()
        print(f'receiver bps: run start time: {self.start_time}')
        while True:
            # Capture frames
            with mss.mss() as sct:
                monitor = {"top": self.y, "left": self.x, "width": self.width, "height": self.height}
                screenshot = np.array(sct.grab(monitor))
            self.grabs.append((int(time.time() + 1), screenshot))
            #print(f'receiver bps: {time.time()}')

            # wait 1 second
            time.sleep(0.96)

            # Check if the duration has elapsed
            if time.time() - self.start_time >= self.duration:
                print(f'receiver bps: total run time: {time.time() - self.start_time}')
                print(f'receiver bps: overall screen shots: {len(self.grabs)}, for duration: {self.duration} seconds')
                break

    def calculate_Bps(self):
        print('\ncalculate bps...')
        prev_et = 0
        for (et, image) in self.grabs:
            if prev_et != 0 and et == prev_et:
                continue
            # Convert NumPy array to PIL Image
            pil_image = Image.fromarray(image)
            pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
            # Perform OCR to extract the text from the image
            extracted_text = pytesseract.image_to_string(pil_image)
            if extracted_text:
                print(f'end time: {et} -- extracted text: {extracted_text}')

                # extract the number from the text
                number_pattern = r'\d+(\.\d+)?'  # Pattern to match decimal numbers
                number_match = re.search(number_pattern, extracted_text)

                if number_match:
                    extracted_number = number_match.group()
                    extracted_number = float(extracted_number)
                    print(f'extracted number: {extracted_number}\n')
                else:
                    print("No number found in the extracted text\n")
                    extracted_number = -1

                self.Bps_list.append((et, int(extracted_number*8000)))   # convert kBps -> bps

            else:   # no text extracted
                self.Bps_list.append((et, -1))

            prev_et = et

        print('\nFinished calculate bps...')

    def display_all_grabs(self):
        print(f'\ntotal screen shots captured: {len(self.grabs)}')
        for (_, image) in self.grabs:
            cv2.imshow('Frame', image)
            # Wait for a key press and then close the window
            cv2.waitKey(0)
            cv2.destroyAllWindows()


def write_to_csv(Bps_list, dir_path):
    filename = dir_path + "\\bpsLabels.csv"
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['bps', 'et']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for (et, Bps) in Bps_list:
            #if Bps == -1 or Bps == 0:
            #    continue
            writer.writerow({'bps': Bps, 'et': et})

    print("\nBps labels csv file was created")


def main():
    time.sleep(3)
    prog_start_time = time.time()
    print(f'receiver bps: start time: {prog_start_time}')

    #duration = 60  # Duration of capture in seconds

    # Check if arguments are provided
    if len(sys.argv) < 4:
        print("Usage: python create_pcap.py <arg1> <arg2>")
        return

    initial_time = sys.argv[1]
    BW = sys.argv[2]
    dir_path = sys.argv[3]
    duration = int(sys.argv[4])  # Duration of capture in seconds

    bps_caculator = BpsCalculator(duration)
    bps_caculator.run()
    print(f'receiver bps: total duration of captures part: {time.time() - prog_start_time}')

    # second part: calculate bps, create csv file
    time.sleep(5)
    bps_caculator.calculate_Bps()
    write_to_csv(bps_caculator.Bps_list, dir_path)
    #bps_caculator.display_all_grabs()

    print(f'\nreceiver bps: total duration the program: {time.time() - prog_start_time}')


if __name__ == "__main__":
    main()
