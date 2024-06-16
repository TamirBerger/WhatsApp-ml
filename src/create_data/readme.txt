screen_capture_ffmpeg: using ffmeg tool for cmd, the script take lossless creen captures.

create_pcap: create pcap file using tshark tool, takes all udp packets.

images2labels_csv: create new csv file with one column 'brisque'. the file contain brisque scores of all the images from the session.

merge_captures: combine 'create_pcap' and 'screen_capture_ffmpeg' together.

pcap2csv: convert the pcap file to csv file.

how to use:
1. begin whatsapp session
2. run merge_captures and change whatsapp video to full screen. wait for timout time.
3. run pcap2csv.
4. run images2labels_csv
5. move pcap_{time}.pcap file pcap_{time}.csv file from pcap_files directory to final_pcap_files directory.
6. create new directory '{time}' in sessions_screen_captures', move all images from 'screen_captures' directory to '{time}' directory.


