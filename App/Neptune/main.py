#################################################################################
# Neptune main program file
#
# File: main.py
# Name: James Aiken
# Date: 25/03/2019
# Course: CSC4006 - Research and Development Project
# Desc: Main class for the Neptune Intrusion Detection System.  It cleans
#      the application's file system and creates a machine learning classifier
#      from the sklearn library.  The main program loop implements live traffic
#      flow classification
#
# Usage: Program is executed from a terminal using 'sudo python Neptune/main.py'
#       Requires a classifier to be specified in nids_config/classifier_type.txt.
#       Relies on the sklearn libraryself.
#
# Requirements: intrusion_detection.py, flow_cleaning.py, traffic_stats.py.
#
# classifier_functions.py is also recommended for the tuning of classifier
# hyperparameters.  Currently they are tuned for the included training set
# for SYN flood detection
#
#################################################################################

import os
import sys
import time
import shutil
import logging
import pandas as pd

from subprocess import Popen, PIPE

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import KMeans

from intrusion_detection import IntrusionDetection
from traffic_stats import TrafficStats
from classifier_training import ClassifierTraining


#################################################################################
# NeptuneNIDS()
#
# Neptune main class to perform network intrusion detection on live traffic
#
# Attributes:
#    batch_number: Each execution begins counting live traffic batches from 1
#    traffic_stats: TrafficStats object for polling for live flow statistics
#    intrusion_detection: IntrusionDetection object to perform ID on flow stats
#    classifier_train: ClassifierTraining object to train the classifier
#
class NeptuneNIDS():

    batch_number = 1
    traffic_stats = TrafficStats()
    intrusion_detection = IntrusionDetection()
    classifier_train = ClassifierTraining()


    #############################################################################
    # __init__()
    #
    # NeptuneNIDS constructor
    #
    # Sets working directory and initialises file system for new execution
    # Initialises the machine learning classifier
    #
    def __init__(self):
        os.chdir(os.getcwd() + "/App/")

        self.initialise_files()
        self.ml_flow = self.classifier_config()


    #############################################################################
    # main()
    #
    # Main method of Neptune, performs main intrusion detection cycle
    # Trains on training statistics, repeatedly requests live statistics and
    # performs intrusion detection based on the detection frequency setting
    #
    def main(self):
        loop_count = 0
        polling_freq = 10
        detection_freq = 10
        retraining_freq = 5

        live_training_flag = False
        trained = False
        retraining = False
        intrusions = []

        # Launch the Argus network auditor as a daemon
        dir = os.getcwd() + "/Neptune/stats_live/traffic.txt"
        cmd = "sudo argus -d -m -i s1-eth10 -w " + dir + " &"
        Popen(['gnome-terminal', '-e', cmd], stdout=PIPE)

        while True:
            if not trained:
                print("Training...")
                #try:
                self.ml_flow = self.classifier_train.model_training(self.ml_flow, False, polling_freq)
                #except:
                #    logging.error('Training error..')
                trained = True
            elif retraining:
                print("Retraining...")
                try:
                    self.ml_flow = self.classifier_train.model_training(self.ml_flow, True, polling_freq)
                except:
                    logging.error('Retraining error..')
                retraining = False

            # Wait for traffic to start flowing
            if self.batch_number == 1:
                time.sleep(10)

            self.traffic_stats.request_stats(self.batch_number, False)

            loop_count += 1
            time.sleep(1)
            if loop_count % (detection_freq/polling_freq) == 0:
                intrusions = self.intrusion_detection.intrusion_detection(intrusions,
                self.ml_flow, live_training_flag, self.batch_number, polling_freq)

            time.sleep(polling_freq)

            if loop_count % retraining_freq == 0 and live_training_flag:
                retraining = True

            self.batch_number += 1

    #############################################################################
    # initialise_files()
    #
    # Resets the Neptune file system for a new execution
    # Deletes files from the previous execution and resets the configuration
    # settings
    #
    def initialise_files(self):

        stats_live_dir = os.getcwd() + "/Neptune/stats_live"

        try:
            shutil.rmtree(stats_live_dir)
            os.makedirs(stats_live_dir)
        except:
            logging.error('Could not initialise stats_live directory')

        try:
            with open('nids_config/intrusion_results.txt', 'w') as intrusion_results:
                print("")
        except:
            logging.error('Could not open intrusion_results file')

        live_traffic_dir = "stats_live/traffic.txt"
        if os.path.exists(live_traffic_dir):
            os.remove(live_traffic_dir)


    #############################################################################
    # classifier_config()
    #
    # Initialises the machine learning classifier based on the configuration
    # setting read from classifier_type.txt
    #
    # The hyperparameters chosen for each model are based on the tuning and
    # evaluation from the classifier_functions.py script
    #
    # classifier_type Args:
    #    1 - Random Forest
    #    2 - KNN
    #    3 - SVC
    #    4 - Neural Network
    #    5 - Logistic Regression
    #
    # Returns:
    #    An sklearn classifier object to implement training and intrusion detection
    #
    def classifier_config(self):

        try:
            classifier_config = open("nids_config/classifier_type.txt", "r")
        except:
            logging.error('Could not open classifier_type file')

        classifier = []
        for val in classifier_config.read().split():
            classifier.append(int(val))
        classifier_config.close()
        classifier_type = classifier[0]

        if classifier_type == 1:
            ml_flow = RandomForestClassifier(bootstrap=True, min_samples_leaf=2,
            n_estimators=200, max_features='sqrt', min_samples_split=10, max_depth=50)
        elif classifier_type == 2:
            ml_flow = KNeighborsClassifier(p=1, weights='distance', algorithm='auto',
            n_neighbors=15)
        elif classifier_type == 3:
            ml_flow = SVC(kernel='linear', C=0.001, gamma=0.0001, probability=True)
        elif classifier_type == 4:
            ml_flow = MLPClassifier(alpha=0.1, solver='adam', hidden_layer_sizes=(50, 50, 50))
        elif classifier_type == 5:
            ml_flow = LogisticRegression(C=0.1, penalty='l2', solver='lbfgs',
            multi_class='ovr')
        elif classifier_type == -1:
            logging.error('Invalid classifier_type, exiting..')
            sys.exit(0)

        return ml_flow


    #############################################################################
    # logo()
    #
    # Display Neptune logo on app launch using print()
    #
    def logo(self):
        os.system('clear')
        logo = '''

        *********************************************************************
                _   __                  __
               / | / /  ___     ____   / /_  __  __   ____   ___
              /  |/ /  / _ /   / __ / / __/ / / / /  / __ / / _ /
             / /|  /  /  __/  / /_/ // /_  / /_/ /  / / / //  __/
            /_/ |_/   /___/  / .___/ /__/  /__,_/  /_/ /_/ /___/
                            /_/
        *********************************************************************
        '''

        print(logo)


if __name__ == '__main__':
    ids = NeptuneNIDS()
    try:
        ids.logo()
        ids.main()
    finally:
        os.system("sudo pkill -f 'argus'") # Terminate Argus daemon
