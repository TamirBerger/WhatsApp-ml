import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt


if __name__ == "__main__":

    csv_file = "C:\\final_project\pcap_files\\2024_04_14_14_06_30KBps\pcap_2024_04_14_14_06_30KBps_ml_WhatsApp_outcomes.csv"

    df = pd.read_csv(csv_file)
    # Calculate the average and standard deviation of the columns 't_burst_count' and 'l_num_unique'
    avg_t_burst_count = df['t_burst_count'].mean()
    std_t_burst_count = df['t_burst_count'].std()

    avg_l_num_unique = df['l_num_unique'].mean()
    std_l_num_unique = df['l_num_unique'].std()

    avg_fps = df['fps'].mean()
    std_fps = df['fps'].std()

    print("Original Data:")
    print("Average t_burst_count:", avg_t_burst_count)
    print("Standard Deviation t_burst_count:", std_t_burst_count)

    print("Average l_num_unique:", avg_l_num_unique)
    print("Standard Deviation l_num_unique:", std_fps)

    print("Average fps:", avg_fps)
    print("Standard Deviation fps:", std_l_num_unique)

    # Filter out rows where the absolute difference from the average is greater than the standard deviation
    filtered_df = df[(df['t_burst_count'] - avg_t_burst_count).abs() <= std_t_burst_count]

    #filtered_df = filtered_df[(filtered_df['l_num_unique'] - avg_t_burst_count).abs() <= std_t_burst_count]

    fps_index = filtered_df.columns.get_loc('fps')

    # Find the indices of the columns 'l_max' and 't_std'
    l_max_index = filtered_df.columns.get_loc('l_max')
    t_std_index = filtered_df.columns.get_loc('t_std')

    # Extract 'fps' column and columns between 'l_max' and 't_std'
    subset_df = filtered_df.iloc[:, [fps_index] + list(range(l_max_index, t_std_index + 1))]

    # Calculate correlation matrix
    correlation_matrix = subset_df.corr()

    # Create heatmap
    plt.figure(figsize=(15, 12))
    sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt=".2f")
    plt.title('Correlation Heatmap')
    plt.show()

