import subprocess
import os
from brisque import BRISQUE
import numpy as np
from PIL import Image  # PIL is used to read the image file
import matplotlib.pyplot as plt
import time
import csv


framerate = 1


def calculate_avg_brisque(image_folder):
    images = [im for im in os.listdir(image_folder) if im.endswith('.png')]
    brisque_model = BRISQUE(url=False)
    avg_brisque_scores = []

    print("calculate brisque scores...")

    for i in range(0, len(images), framerate):
        batch_images = images[i:i + framerate]
        batch_scores = []

        for im in batch_images:
            image_path = image_folder + "\\" + im
            image = Image.open(image_path)
            image_array = np.array(image)

            score = brisque_model.score(image_array)
            batch_scores.append(score)

        average_score = np.mean(batch_scores)
        avg_brisque_scores.append(average_score)

    return avg_brisque_scores


def write_to_csv(scores, filename):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['brisque']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for score in scores:
            writer.writerow({'brisque': score})

    print("labels csv file was created")


if __name__ == "__main__":
    capture_folder = "C:\\final_project\screen_captures"
    output_csv = "C:\\final_project\labels_csv"

    # Ensure the output_csv directory exists
    if not os.path.exists(output_csv):
        os.makedirs(output_csv)

    # give name to the labels csv file with same ending as the pcap csv file (time)
    pcap_dir_path = "C:\\final_project\pcap_files"
    for t in os.listdir(pcap_dir_path):
        if t.endswith('.pcap'):
            output_csv = f"{output_csv}/labels{t[4:-5]}.csv"
            break

    # output_csv = os.path.join(output_csv, "average_brisque_scores.csv")

    # Calculate and write average BRISQUE scores to CSV
    average_scores = calculate_avg_brisque(capture_folder)

    print("\nAverage BRISQUE Scores:")
    for i, score in enumerate(average_scores, start=1):
        print(f"average of second {i}: {score}")

    write_to_csv(average_scores, output_csv)


