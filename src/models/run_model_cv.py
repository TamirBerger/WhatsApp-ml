from collections import defaultdict
from itertools import product
from datetime import datetime as dt
import pandas as pd
from pathlib import Path
from sklearn.metrics import mean_absolute_error, accuracy_score, r2_score
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from xgboost import XGBClassifier, XGBRegressor
from catboost import CatBoostRegressor, CatBoostClassifier

import os
import time
import sys
from os.path import dirname, abspath, basename

project_root = dirname(dirname(abspath(__file__)))
sys.path.append(project_root)
print(project_root)
print(sys.path)
from util.config import project_config
import pickle
# from util.file_processor import FileProcessor
# from util.file_processor import FileValidator
# from util.data_splitter import KfoldCVOverFiles
from models.ip_udp_ml import IP_UDP_ML
from models.rtp_ml_ours import RTP_ML

from models.ip_udp_heuristic import IP_UDP_Heuristic
from util.helper_functions import create_file_tuples_list, KfoldCVOverFiles, create_file_tuples_list_rtp


class ModelRunner:

    def __init__(self, metric, estimation_method, feature_subset, data_dir, cv_index, my_ip_l,
                 net_conditions_train, net_conditions_test):

        self.metric = metric  # label
        self.estimation_method = estimation_method  # model name
        self.estimator = RandomForestClassifier() if self.metric == 'resolution' or self.metric == 'fps' \
            else RandomForestRegressor()
        #self.estimator = XGBClassifier() if self.metric == 'resolution' or self.metric == 'fps' \
        #    else XGBRegressor()
        #self.estimator = CatBoostClassifier(logging_level='Silent') if self.metric == 'resolution' or self.metric == 'fps' \
        #    else CatBoostRegressor(logging_level='Silent')
        # features subset from ['SIZE' 'IAT', 'LSTATS', 'TSTATS']
        self.feature_subset = 'none' if feature_subset is None else feature_subset
        self.data_dir = data_dir

        if feature_subset:
            feature_subset_tag = '-'.join(feature_subset)
        else:
            feature_subset_tag = 'none'

        net_cond_train_tag = '-'.join(net_conditions_train)
        net_cond_test_tag = '-'.join(net_conditions_test)

        data_bname = os.path.basename(data_dir)

        self.trial_id = '_'.join(
            [metric, net_cond_train_tag, self.estimation_method,
             net_cond_test_tag, f'cv_idx{cv_idx}'])

        self.intermediates_dir = f'{self.data_dir}_intermediates/{self.trial_id}'

        self.cv_index = cv_index

        self.model = None

        self.my_ip_l = my_ip_l

    def save_intermediate(self, data_object, pickle_filename):
        pickle_filename = f'{self.trial_id}_{pickle_filename}'
        pickle_filepath = f'{self.intermediates_dir}/{pickle_filename}.pkl'

        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(pickle_filepath), exist_ok=True)

        # Save the intermediate data object to a pickle file
        with open(pickle_filepath, 'wb') as fd1:
            pickle.dump(data_object, fd1)

    def load_intermediate(self, pickle_filename):
        with open(f'{self.intermediates_dir}/{pickle_filename}.pkl', 'rb') as fd:
            data_object = pickle.load(fd)
        return data_object

    def fps_prediction_accuracy(self, pred, truth):
        # check accuracy of frame per second prediction
        # correct if |pred - label| <= 2, else incorrect
        n = len(pred)
        df = pd.DataFrame({'pred': pred.to_numpy(), 'truth': truth.to_numpy()})
        df['deviation'] = df['pred'] - df['truth']
        df['deviation'] = df['deviation'].abs()
        return len(df[df['deviation'] <= 2]) / n

    def bps_prediction_accuracy(self, pred, truth):
        # check accuracy of bit per second prediction
        # correct if |pred - label| <= 10% of label, else incorrect
        n = len(pred)
        df = pd.DataFrame({'pred': pred.to_numpy(), 'truth': truth.to_numpy()})
        df['abs_diff'] = (df['pred'] - df['truth']).abs()
        df['threshold'] = df['truth'] * 0.1
        correct_predictions = df[df['abs_diff'] <= df['threshold']]
        # Return the accuracy
        return len(correct_predictions) / n

    def brisque_prediction_accuracy(self, pred, truth):
        # check accuracy of brisque prediction
        # correct if |pred - label| <= 5, else incorrect
        n = len(pred)
        df = pd.DataFrame({'pred': pred.to_numpy(), 'truth': truth.to_numpy()})
        df['deviation'] = df['pred'] - df['truth']
        df['deviation'] = df['deviation'].abs()
        return len(df[df['deviation'] <= 5]) / n

    def train_model(self, split_files):
        bname = os.path.basename(self.data_dir)

        if self.estimation_method == 'ip-udp-ml':

            model = IP_UDP_ML(
                feature_subset=self.feature_subset,
                estimator=self.estimator,
                config=project_config,
                metric=self.metric,
                dataset=bname,
                my_ip_l=self.my_ip_l
            )
            model.train(split_files)

        elif self.estimation_method == 'rtp-ml':

            model = RTP_ML(
                feature_subset=self.feature_subset,
                estimator=self.estimator,
                config=project_config,
                metric=self.metric,
                dataset=bname,
                my_ip_l=self.my_ip_l
            )
            model.train(split_files)

        elif self.estimation_method == 'ip-udp-heuristic':
            model = IP_UDP_Heuristic(
                vca=vca, metric=self.metric, config=project_config, dataset=bname)

        vca_model = model
        #self.save_intermediate(vca_model, 'vca_model')
        return vca_model

    def get_test_set_predictions(self, split_files, vca_model):
        predictions = []
        maes = []
        accs = []
        r2_scores = []

        idx = 1
        total = len(split_files)
        for file_tuple in split_files:
            #print(file_tuple[0])
            model = vca_model
            print(
                f'Testing {self.estimation_method} on file {idx} out of {total}...')
            output = model.estimate(file_tuple)

            output = output.dropna()

            if output is None:
                idx += 1
                predictions.append(output)
                continue

            # if the model isn't classifier calculate MAE and R2 score
            if self.metric != 'resolution':
                mae = mean_absolute_error(
                    output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
                print(f'MAE = {round(mae, 2)}')
                maes.append(mae)

                r2 = r2_score(
                    output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
                print(f'R2 score = {round(r2, 2)}')
                r2_scores.append(r2)

            else:  # classifier model: calculate classification accuracy
                a = accuracy_score(
                    output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
                print(f'Accuracy = {round(acc, 2) * 100}%')
                accs.append(a)

            # calculate fps prediction accuracy (correct: absolute difference <= 2)
            if self.metric == 'fps':
                acc = self.fps_prediction_accuracy(
                    output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
                accs.append(acc)
                print(f'Accuracy = {round(acc, 2) * 100}%')

            # calculate bps prediction accuracy (correct: absolute difference <= 10% of truth)
            if self.metric == 'bps':
                acc = self.bps_prediction_accuracy(
                    output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
                accs.append(acc)
                print(f'Accuracy = {round(acc, 2) * 100}%')

            # calculate bps prediction accuracy (correct: absolute difference <= 5)
            if self.metric == 'brisque':
                acc = self.brisque_prediction_accuracy(
                    output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
                accs.append(acc)
                print(f'Accuracy = {round(acc, 2) * 100}%')

            idx += 1
            predictions.append(output)
            print("---------\n")

        if self.metric == 'resolution':
            mae_avg = "None"
        else:
            mae_avg = round(sum(maes) / len(maes), 2)
            r2_avg = round(sum(r2_scores) / len(r2_scores), 2)
        accuracy_str = ''
        if self.metric == 'fps' or self.metric == 'bps' or self.metric == 'brisque':
            acc_avg = round(100 * sum(accs) / len(accs), 2)
            accuracy_str = f'|| Accuracy_avg = {acc_avg}'
        line = f'{dt.now()}\tExperiment : {self.trial_id} || MAE_avg = {mae_avg} || R2_avg = {r2_avg} {accuracy_str}\n'
        with open('C:\\final_project\git_repo\data_collection_intermediates\\log-rand_split-rf.txt', 'a') as fd1:
            fd1.write(line)

        #self.save_intermediate(predictions, 'predictions')
        return predictions

    def get_avg_cv_predictions(self, output):

        maes = []
        accs = []
        r2_scores = []

        # if the model isn't classifier calculate MAE and R2 score
        if self.metric != 'resolution':
            mae = mean_absolute_error(
                output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
            print(f'MAE = {round(mae, 2)}')
            maes.append(mae)

            r2 = r2_score(
                output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
            print(f'R2 score = {round(r2, 2)}')
            r2_scores.append(r2)

        else:  # classifier model: calculate classification accuracy
            a = accuracy_score(
                output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
            print(f'Accuracy = {round(a, 2) * 100}%')
            accs.append(a)

        # calculate fps prediction accuracy (correct: absolute difference <= 2)
        if self.metric == 'fps':
            acc = self.fps_prediction_accuracy(
                output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
            accs.append(acc)
            print(f'Accuracy = {round(acc, 2) * 100}%')

        # calculate bps prediction accuracy (correct: absolute difference <= 10% of truth)
        if self.metric == 'bps':
            acc = self.bps_prediction_accuracy(
                output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
            accs.append(acc)
            print(f'Accuracy = {round(acc, 2) * 100}%')

        # calculate bps prediction accuracy (correct: absolute difference <= 5)
        if self.metric == 'brisque':
            acc = self.brisque_prediction_accuracy(
                output[f'{self.metric}_gt'], output[f'{self.metric}_{self.estimation_method}'])
            accs.append(acc)
            print(f'Accuracy = {round(acc, 2) * 100}%')

        print("---------\n")

        if self.metric == 'resolution':
            mae_avg = "None"
        else:
            mae_avg = round(sum(maes) / len(maes), 2)
            r2_avg = round(sum(r2_scores) / len(r2_scores), 2)
        accuracy_str = ''
        if self.metric == 'fps' or self.metric == 'bps' or self.metric == 'brisque':
            acc_avg = round(100 * sum(accs) / len(accs), 2)
            accuracy_str = f'|| Accuracy_avg = {acc_avg}'
        line = f'{dt.now()}\tExperiment : {self.trial_id[:-1]}avg || MAE_avg = {mae_avg} || R2_avg = {r2_avg} {accuracy_str}\n'
        with open('C:\\final_project\git_repo\data_collection_intermediates\\log-avg-rand_split-rf.txt', 'a') as fd1:
            fd1.write(line)

        #self.save_intermediate(output, 'predictions_cv-avg')


if __name__ == '__main__':
    # Example usage

    my_ip_l = ['10.100.102.32', '192.168.0.102', '10.0.0.115']
    metrics = ['fps', 'brisque']  # what to predict
    estimation_methods = ['rtp-ml', 'ip-udp-ml']  # model selection
    #estimation_methods = ['ip-udp-heuristic', 'ip-udp-ml']  # how to predict

    # groups of features as per `features.feature_extraction.py`
    feature_subsets = [['LSTATS', 'TSTATS']]
    # network conditions set
    net_conditions = ["bandwidth", "loss", "falls", "bandwidth_old"]
    # train/test network conditions subset
    net_conditions_train = [["falls"]]
    net_conditions_test = [["falls"]]

    data_dir = ["C:\\final_project\git_repo\data_collection"]


    bname = os.path.basename(data_dir[0])

    # Create a directory for saving model intermediates
    intermediates_dir = f'{data_dir[0]}_intermediates'
    Path(intermediates_dir).mkdir(exist_ok=True, parents=True)

    # Get a list of pairs (trace_csv_file, ground_truth)
    #fp = FileProcessor(data_directory=data_dir[0])
    #file_dict = fp.get_linked_files()

    # Create 5-fold cross validation splits and validate files. Refer `util/validator.py` for more details

    kcv = KfoldCVOverFiles(5, data_dir[0], net_conditions, metrics, None, False)
    file_splits = kcv.split()

    #with open(f'{intermediates_dir}/cv_splits.pkl', 'wb') as fd:
    #    pickle.dump(file_splits, fd)

    #vca_preds = defaultdict(list)

    param_list = [metrics, estimation_methods, feature_subsets, net_conditions_train, net_conditions_test, data_dir]

    # Run models over 5 cross validations
    n = 1
    for metric, estimation_method, feature_subset, net_conds_subset_train, net_conds_subset_test, data_dir in product(*param_list):
        if metric == 'brisque' and 'heuristic' in estimation_method:
            continue
        vca_preds = []
        metric_net_cond_preds = []
        models = []
        cv_idx = 1
        for fsp in file_splits:

            # create train and test file tuples lists
            train_file_tuple_list = []
            for net_cond in net_conditions:
                if net_cond in net_conds_subset_train:
                    train_file_tuple_list += fsp[net_cond][metric]["train"]

            test_file_tuple_list = []
            for net_cond in net_conditions:
                if net_cond in net_conds_subset_test:
                    test_file_tuple_list += fsp[net_cond][metric]["test"]

            model_runner = ModelRunner(
                metric, estimation_method, feature_subset, data_dir, cv_idx, my_ip_l, net_conds_subset_train, net_conds_subset_test)
            vca_model = model_runner.train_model(train_file_tuple_list)
            Path(f'{intermediates_dir}/{model_runner.trial_id}').mkdir(exist_ok=True, parents=True)
            predictions = model_runner.get_test_set_predictions(test_file_tuple_list, vca_model)
            models.append(vca_model)
            #with open(f'{intermediates_dir}/{model_runner.trial_id}/model.pkl', 'wb') as fd:
            #    pickle.dump(vca_model, fd)
            preds = pd.concat(predictions, axis=0)
            vca_preds.append(preds)
            #with open(f'{intermediates_dir}/{model_runner.trial_id}/predictions.pkl', 'wb') as fd:
            #    pickle.dump(preds, fd)
            cv_idx += 1
            metric_net_cond_preds.append(preds)

        cmobine_preds = pd.concat(vca_preds, axis=0)
        cmobine_preds.to_csv(f'cmobine_preds_{metric}_{"-".join(net_conds_subset_train)}_{"-".join(net_conds_subset_test)}_{n}.csv', index=False)
        n += 1

        print(f'===========================\n===========================\n'
              f'train net condition subset: {" ".join(net_conds_subset_train)}\n'
              f'test net condition subset: {" ".join(net_conds_subset_test)}\n'
              f'metric: {metric}\n'
              f'===========================\n===========================\n'
              )
        model_runner.get_avg_cv_predictions(cmobine_preds)

