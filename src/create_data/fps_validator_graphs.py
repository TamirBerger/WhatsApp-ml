import pandas as pd
import matplotlib.pyplot as plt
import glob
import seaborn as sns
import os
import re
import numpy as np


# Function to read and clean the CSV files
def load_and_clean_data(file_pattern):
    all_files = glob.glob(file_pattern)
    df_list = []

    for i, file in enumerate(all_files):
        df = pd.read_csv(file)
        df = df.iloc[1:-1]  # Discarding the first and last samples
        if 'screenshots_num' in df.columns:  # Discarding samples with less than 45 screenshots
            initial_count = len(df)
            df = df[df['screenshots_num'] >= 35]
            removed_count = initial_count - len(df)
            print(f'File {i}: Removed {removed_count} samples with screenshots_num < 35')
        print("")

        # Extract FPS label from file name
        fps_label = int(re.search(r'fpsLabels_(\d+)', os.path.basename(file)).group(1))
        df['fps_label'] = fps_label
        df_list.append(df)

    return df_list


# Function to compute MAE for each FPS
def compute_mae(df_list):
    mae_values = []

    for df in df_list:
        fps_label = df['fps_label'].iloc[0]
        mae = df['fps'].sub(fps_label).abs().mean()
        mae_values.append((fps_label, mae))

    return mae_values


# Function to create frame rate errors plot
def create_frame_rate_errors_plot(df_list):

    fps_labels = [df['fps_label'].iloc[0] for df in df_list]
    fps_errors = [df['fps'].sub(df['fps_label'].iloc[0]) for df in df_list]

    # Concatenate all the Series objects in fps_errors into a single numpy array
    fps_errors_concatenated = np.concatenate(fps_errors)

    # Calculate the MAE for each FPS
    mae_values = [errors.abs().mean() for errors in fps_errors]
    # Calculate the lower and upper whiskers
    lower_whisker = np.percentile(fps_errors_concatenated, 10)
    upper_whisker = np.percentile(fps_errors_concatenated, 90)

    # Create the box plot with percentiles and MAE annotations
    fig, ax = plt.subplots(figsize=(10, 6))

    # Set the y-axis limits closer to the whiskers
    # ax.set_ylim(lower_whisker - 2 * (upper_whisker - lower_whisker),
    #            upper_whisker + 2 * (upper_whisker - lower_whisker))
    ax.set_ylim(lower_whisker - 2,
                upper_whisker + 2)
    box = ax.boxplot(fps_errors, labels=fps_labels, showmeans=True, whis=[10, 90], flierprops=dict(marker=''))

    # Annotate the plot with MAE values
    for i, line in enumerate(box['medians']):
        x, y = line.get_xydata()[1]
        ax.text(x, y, f'{mae_values[i]:.1f}', horizontalalignment='center', verticalalignment='bottom')

    ax.set_xlabel('FPS')
    ax.set_ylabel('FPS Error')
    ax.set_title('Frame Rate Errors with 10th and 90th Percentile Whiskers and MAE Annotations')
    plt.show()


# Function to create frame rate errors plot for FPS ranges
def create_frame_rate_errors_plot_by_range(df_list):

    ranges = [(0, 5), (5, 10), (10, 15), (15, 20), (20, 25), (25, 30)]
    range_labels = ['0-5', '5-10', '10-15', '15-20', '20-25', '25-30']
    range_errors = {label: [] for label in range_labels}

    for df in df_list:
        fps_label = df['fps_label'].iloc[0]
        fps_error = df['fps'].sub(fps_label)

        for i, (start, end) in enumerate(ranges):
            if start <= fps_label < end:
                range_errors[range_labels[i]].extend(fps_error.tolist())
                break

    # Filter out empty ranges
    non_empty_labels = [label for label in range_labels if range_errors[label]]
    non_empty_errors = [range_errors[label] for label in non_empty_labels]

    if not non_empty_errors:
        print("No valid ranges with data after filtering.")
        return

    # Concatenate all the errors data into a single list for adjusting y-axis range
    all_errors = np.concatenate(non_empty_errors)

    # Calculate the MAE values for each range
    mae_values = [np.mean(np.abs(errors)) for errors in non_empty_errors]

    # Calculate the lower and upper whiskers
    lower_whisker = np.percentile(all_errors, 10)
    upper_whisker = np.percentile(all_errors, 90)

    # Create the box plot with percentiles and MAE annotations for ranges
    fig, ax = plt.subplots(figsize=(10, 6))

    # Set the y-axis limits closer to the whiskers
    #ax.set_ylim(lower_whisker - 2 * (upper_whisker - lower_whisker),
    #            upper_whisker + 2 * (upper_whisker - lower_whisker))
    ax.set_ylim(lower_whisker - 2,
                upper_whisker + 2)

    # Plot the boxplot without outliers
    box = ax.boxplot(non_empty_errors, labels=non_empty_labels, showmeans=True, whis=[10, 90], flierprops=dict(marker=''),
                     patch_artist=True,  # Fill the box with color
                     boxprops=dict(color='black', linewidth=3),
                     medianprops=dict(color='orange', linewidth=3),
                     whiskerprops=dict(color='black', linewidth=2),
                     capprops=dict(color='black', linewidth=2))

    # Fill the boxes with color
    colors = ['lightblue'] * len(non_empty_labels)
    for patch, color in zip(box['boxes'], colors):
        patch.set_facecolor(color)

    # Annotate the plot with MAE values
    for i, line in enumerate(box['medians']):
        x, y = line.get_xydata()[1]
        ax.text(x, y, f'{mae_values[i]:.1f}', horizontalalignment='center', verticalalignment='bottom', fontsize=20)

    ax.tick_params(axis='both', which='major', labelsize=20)  # Making axis numbers larger
    ax.set_xlabel('FPS Range', fontsize=28, labelpad=20)
    ax.set_ylabel('FPS Error', fontsize=28, labelpad=20)
    #ax.set_title('Frame Rate Errors by FPS Range with 10th and 90th Percentile Whiskers and MAE Annotations')

    # Add horizontal grid to the plot
    ax.yaxis.grid(True)
    ax.xaxis.grid(False)

    plt.tight_layout()
    plt.show()


# Create histogram of FPS errors
def create_histogram(df_list):
    plt.figure(figsize=(10, 6))

    for df in df_list:
        fps_label = df['fps_label'].iloc[0]
        fps_errors = df['fps'].sub(fps_label)
        plt.hist(fps_errors, bins=20, alpha=0.5, label=f'FPS {fps_label}')

    plt.xlabel('FPS Error')
    plt.ylabel('Frequency')
    plt.title('Histogram of FPS Errors')
    plt.legend(loc='upper right')
    plt.show()


# Create density plot of FPS errors
def create_density_plot(df_list):
    plt.figure(figsize=(12, 6))

    for df in df_list:
        fps_label = df['fps_label'].iloc[0]
        fps_errors = df['fps'].sub(fps_label) + np.random.normal(0, 0.001, size=len(df))
        fps_errors.plot(kind='density', alpha=0.5, label=f'FPS {fps_label}')

    plt.xlabel('FPS Error')
    plt.ylabel('Density')
    plt.title('Density Plot of FPS Errors')
    plt.legend(loc='upper right')
    plt.show()


# Create heatmap of FPS errors
def create_heatmap(df_list):
    heatmap_data = pd.DataFrame()

    for df in df_list:
        fps_label = df['fps_label'].iloc[0]
        df['fps_error'] = df['fps'].sub(fps_label)
        df = df.pivot(index='et', columns='fps_label', values='fps_error')
        heatmap_data = pd.concat([heatmap_data, df], axis=1)

    plt.figure(figsize=(12, 6))
    sns.heatmap(heatmap_data, cmap='coolwarm', center=0)
    plt.xlabel('FPS Label')
    plt.ylabel('End Time')
    plt.title('Heatmap of FPS Errors')
    plt.show()


def compute_overall_metrics(df_list, tolerance=0.05):
    all_errors = []
    correct_predictions = 0
    total_predictions = 0

    for df in df_list:
        fps_label = df['fps_label'].iloc[0]
        fps_error = df['fps'].sub(fps_label).abs()
        all_errors.extend(fps_error.tolist())

        within_tolerance = fps_error <= (tolerance * fps_label)
        correct_predictions += within_tolerance.sum()
        total_predictions += len(df)

    overall_mae = np.mean(all_errors)
    accuracy = correct_predictions / total_predictions

    return overall_mae, accuracy


# Load and clean data
file_pattern = "C:\\final_project\\fps validator measurements new\\fpsLabels_*.csv"
df_list = load_and_clean_data(file_pattern)

# Compute MAE
mae_values = compute_mae(df_list)

# Compute overall MAE and acc
mae, accuracy = compute_overall_metrics(df_list)
print("Overall MAE:", mae)
print("Accuracy:", accuracy)

# Create frame rate errors plot
create_frame_rate_errors_plot(df_list)

# Create frame rate errors plot by FPS range
create_frame_rate_errors_plot_by_range(df_list)

# Create histogram of FPS errors
#create_histogram(df_list)

# Create density plot
#create_density_plot(df_list)

# Create heatmap
#create_heatmap(df_list)

# Display MAE values
mae_df = pd.DataFrame(mae_values, columns=['FPS', 'MAE'])
print(mae_df)