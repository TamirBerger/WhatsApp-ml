import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def plot_density(df_list, metric, bw_adjust=1):
    # Define the desired order of the labels and corresponding line formats
    desired_order = ['250 KBps', '125 KBps', '60 KBps', '30 KBps', '15 KBps']
    line_formats = ['-', '-', '-', '--', '-.']  # Different line styles
    colors = ['blue', 'orange', 'green', 'red', 'purple']  # Different colors

    # Reorder df_list based on the desired order
    reordered_df_list = []
    for label in desired_order:
        for df in df_list:
            df_label = df['grp_name'].iloc[0].split('d')[1]
            if df_label == label:
                reordered_df_list.append(df)
                break

    plt.figure(figsize=(10, 6))
    for df, line_format, color in zip(reordered_df_list, line_formats, colors):
        label = df['grp_name'].iloc[0].split('d')[1]
        sns.kdeplot(df[metric], label=label, bw_adjust=bw_adjust, linewidth=2.4, linestyle=line_format, color=color)

    plt.legend(fontsize=22, title_fontsize='20', loc='upper center', frameon=False,
               shadow=True, bbox_to_anchor=(0.5, 1.28), ncol=3)
    plt.grid(True)
    plt.tick_params(axis='both', which='major', labelsize=30)  # Making axis numbers larger
    plt.xlabel('', fontsize=34, labelpad=20)
    plt.ylabel('Probability density', fontsize=30, labelpad=20)
    plt.tight_layout()  # Adjust layout to fit labels properly
    plt.show()



def plot_cdf(df_list, metric):
    plt.figure(figsize=(10, 6))
    for df in df_list:
        label = df['grp_name'].iloc[0].split('d')[1]
        sorted_data = np.sort(df[metric])
        yvals = np.arange(len(sorted_data))/float(len(sorted_data) - 1)
        plt.plot(sorted_data, yvals, label=label)
    plt.legend(loc='upper left')
    plt.title(f"CDF of {metric}")
    plt.xlabel(metric)
    plt.ylabel("CDF")
    plt.show()

def plot_histogram(df_list, metric, bins=30):
    plt.figure(figsize=(10, 6))
    for df in df_list:
        label = df['grp_name'].iloc[0].split('d')[1]
        plt.hist(df[metric], bins=bins, alpha=0.5, label=label)
    plt.legend(loc='upper right')
    plt.title(f"Histogram of {metric}")
    plt.xlabel(metric)
    plt.ylabel("Frequency")
    plt.show()


file_path = "C:\\final_project\paper\\bandwidth"
df_list = []
for file in os.listdir(file_path):
    if file.startswith("combined"):
        df = pd.read_csv(os.path.join(file_path, file))
        df['grp_name'] = file.split('.')[0]
        df_list.append(df)

plot_density(df_list,'fps', bw_adjust=1)
plot_density(df_list,'brisque', bw_adjust=1)
plot_density(df_list,'piqe', bw_adjust=1)

#plot_cdf(df_list,'fps')
#plot_cdf(df_list,'brisque')
#plot_cdf(df_list,'piqe')

#plot_histogram(df_list,'fps')
#plot_histogram(df_list,'brisque')
#plot_histogram(df_list,'piqe')
