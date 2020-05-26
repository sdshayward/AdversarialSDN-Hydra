#################################################################################
# Neptune Intrusion Detection class
#
# File: intrusion_detection.py
# Name: James Aiken
# Date: 25/03/2019
# Course: CSC4006 - Research and Development Project
# Desc: Class to enable Neptune's Intrusion Detection.  Uses ML classifier to
#       predict each flow entry of the specified batch number.  Records intrusions
#       in a dictionary and outputs to terminal
#
#
# Usage: intrusion_detection() method is called with relevant parameters by
#        the Neptune main.py class.  Provides the main Neptune class with a dictionary
#        of intrusions
#
# Requirements: flow_cleaning.py
#
#################################################################################

import time
import pandas as pd
import logging
import os

from flow_cleaning import FlowCleaning

#################################################################################
# IntrusionDetection() class
#
#
# Class containing all functionality to implement intrusion detection using
# machine learning classifier on live traffic batches
#
# Attributes:
#   last_flow_count: integer to count the number of flows predicted for
#                    live training implementation
#
class IntrusionDetection:

    last_flow_count = 0
    flow_clean = FlowCleaning()

    #############################################################################
    # intrusion_detection(intrusions, ml_flow, live_training_flag, batch_num, poll_dur)
    #
    # Main intrusion detection function which calls appropriate functions to carry
    # out classification
    #
    # Args:
    #    intrusions: dictionary of previously detected intrusions
    #    ml_flow: machine learning model
    #    live_training_flag: boolean to decide whether live training is implemented
    #    batch_num: Flow batch to implement intrusion detection on
    #    poll_dur: Duration between batch polling for flow stats, required for cleaning
    #
    # Returns:
    #    intrusions: dictionary of previous intrusions + new ones detected from current batch
    #                key used uniquely identifies a device on the network
    #
    def intrusion_detection(self, intrusions, ml_flow, live_training_flag, batch_num, poll_dur):

        print("Implementing Intrusion Detection..")

        cleaned_batch = "Neptune/stats_live/output" + str(batch_num) + "_cleaned.csv"
        self.flow_clean.flow_stat_clean(True, batch_num, poll_dur)

        flow_predict = pd.read_csv(
            cleaned_batch,
            skip_blank_lines=True)

        # Convert from string to numeric, excluding eth addresses
        flow_eth = flow_predict.iloc[:,:2]
        flow_predict = flow_predict.iloc[:,2:].apply(pd.to_numeric)

        # Convert to lists for iteration
        flow_predict_list = list(flow_predict.values.tolist())

        flow_predict_counter = 0
        for i in flow_predict_list:
            if i == ['eth_src','eth_dst','ip_proto','state_flag','pkts','src_pkts','dst_pkts','bytes','src_bytes',
                     'dst_bytes','pkts_per_sec','bytes_per_second','bytes_per_packet','packet_pair_ratio','pair_flow']:
                continue
            else:
                flow_predict_counter += 1
                temp = list(i)
                test = []
                test.append(temp)

                # Binary classification on flow stat
                flag_flow = ml_flow.predict(test)
                if flag_flow == 1:
                    proba = ml_flow.predict_proba(test)
                    intrusions = self.anomaly_specific_actions(True, flow_predict_counter-1, i, flow_eth, intrusions, proba)

                    if live_training_flag:
                        self.live_training(1,i,flow_eth,flow_predict_counter)

                else:
                    # self.anomaly_specific_actions(False, flow_predict_counter, i, flow_eth, intrusions)
                    # Not intrusion => do nothing

                    if live_training_flag:
                        self.live_training(0,i,flow_eth,flow_predict_counter)

        self.last_flow_count = flow_predict_counter

        return intrusions


    #############################################################################
    # live_training(malicious_flag, flow_counter, flow_eth, flow_predict_counter)
    #
    # Save classified flows into training directory along with target for live
    # training
    #
    # Args:
    #    malicious_flag: True if flow was classified as malicious
    #    flow_counter: counter to indicate the index of the detected flow
    #    flow_eth: mac addresses for classified flow
    #    flow_predict_counter: counter for the number of flows predicted in batch
    #
    def live_training(self, malicious_flag, flow_counter, flow_eth, flow_predict_counter):

        if self.last_flow_count < flow_predict_counter:
            with open("Neptune/stats_training/FlowStats_target_cleaned.txt", "a") as flow_target_cleaned:
                if malicious_flag == 0:
                    flow_target_cleaned.write("\n0")
                else:
                    flow_target_cleaned.write("\n1")
            with open("Neptune/stats_training/FlowStats_cleaned.txt", "a") as flow_stats_cleaned:
                flow_stats_cleaned.write(str(flow_eth.iloc[flow_predict_counter-1,0]))
                flow_stats_cleaned.write(",")
                flow_stats_cleaned.write(str(flow_eth.iloc[flow_predict_counter-1,1]))
                flow_stats_cleaned.write(",")
                for x in range(len(flow_counter)):
                    flow_stats_cleaned.write(str(flow_counter[x]))
                    if x != len(flow_counter)-1:
                        flow_stats_cleaned.write(",")
                flow_stats_cleaned.write("\n")


    #############################################################################
    # anomaly_specific_actions(flag_flow, flow_predict_counter, flow_stats, flow_eth, intrusions)
    #
    # Handle functionality when a flow is predicted as anomalous
    # Checks if the intrusion has alread been detected, if not, record it
    #
    # Args:
    #    flag_flow: classification of stat
    #    flow_predict_counter: index of flow predicted from the original batch array
    #    flow_stats: flow stat predicted
    #    flow_eth: eth addresses of flow stat predicted
    #    intrusions: dictionary of previous intrusions
    #
    # Returns:
    #    intrusions: updated intrusion dictionary
    #
    def anomaly_specific_actions(self, flag_flow, flow_predict_counter, flow_stats, flow_eth, intrusions, proba):

        if (flag_flow):

            known = False
            stats = [0, 0]
            stat_count = 0

            for i in flow_stats:
                if stat_count == 0 or stat_count == 1:
                    stats[stat_count] = int(i)
                    stat_count += 1
                else:
                    break

            for intrusion in intrusions:
                if str(intrusion) == str(str(flow_eth.iloc[flow_predict_counter,0]) + "," +
                                          str(flow_eth.iloc[flow_predict_counter,1]) + "," + str(stats[0]) + "," +
                                          str(stats[1])):
                    known = True
                    break

            # Output intrusion details to console and file if new intrusion
            if str(flow_eth.iloc[flow_predict_counter,0]) == '-1':
                valid = False
            else:
                valid = True

            if not known and valid:
                print("**Intrusion Detected** - " + str(str(flow_eth.iloc[flow_predict_counter,0]) + "," +
                                          str(flow_eth.iloc[flow_predict_counter,1]) + "," + str(stats[0]) + "," +
                                          str(stats[1]) + " " + str(proba)))

                try:
                    with open('nids_config/intrusion_results.txt', 'a+') as results:
                        results.write("{},{},{},{}\n"
                                      .format(str(flow_eth.iloc[flow_predict_counter,0]),
                                              str(flow_eth.iloc[flow_predict_counter,1]),str(stats[0]),str(stats[1])))
                except:
                    logging.error('Unable to write intrusion results')


                intrusions.append(str(str(flow_eth.iloc[flow_predict_counter,0]) + "," +
                                      str(flow_eth.iloc[flow_predict_counter,1]) + "," + str(stats[0]) + "," +
                                      str(stats[1])))

        # else if not anomalous, do nothing

        return intrusions
