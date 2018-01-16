# -------------------------------------------------------------------
# Title: initial data investigation
# Author: Kalea Sebesta
# Date: 01/13/2017
# Purpose: This file will merge two existing files of pcap data
# together and run an initial investigation to see what preprocessing
# and data cleaning needs to be done. Prior to merging the data sets
# the pcap_output_0001.csv needs to have two columns added and imputed
# with "unknown" so that the variable are the same in both files
# -------------------------------------------------------------------

# import libraries
import pandas as pd
import numpy as np

# -------------------------------------------------------------------
# get data
# -------------------------------------------------------------------
# set directory
dir = '/Volumes/UTSA QRT2/DA 6813 Data Analytics Applications/Project 1/Data/'

# read in excel
main_df= pd.read_excel(dir+"MainOutput.xlsx", sheet_name='Sheet1')
# get list of columns
main_dfColN=list(main_df)

# read in csv
pcap = pd.read_csv(dir+'pcap_output_0001.csv')
# get list of columns
pcapColN=list(pcap)

# add columns (Name, Mal) to file so that the cvs and the excel have the same variables
# Mal = 0 means it is unknown if the data is malicious
pcap['Name'] = 'Unknown'
pcap['Mal'] = 0

# merge files together
pcap_merged = pd.concat([main_df, pcap])

# -------------------------------------------------------------------
# initial investigation
# -------------------------------------------------------------------
# find amount of missing data
# 19 columns out of 23 have at least one null value
''' Missing data columns = ['ACKSEQ', 'DATALENGTH', 'DONOTFRAGMENT', 'DSTIP', 
        'DSTPORT', 'ID', 'IPPKTLEN', 'MOREFRAGMENTS', 'PROTOCOL', 'SCRMACADDR', 
        'SEQ', 'SRCIP', 'SRCMACADDR', 'SRCPORT', 'TIMESTAMP', 'TOS', 'TTL', 
        'URGENTPTR', 'WINDOW']
'''
colMiss=pcap_merged.columns[pcap_merged.isnull().any()]
# calculates and prints out the amount of missing values in each of the column
# that has missing data along with the percent of missing data
for col in colMiss:
    value=sum(pd.isnull(pcap_merged[col]))
    print(col, value, "Percent of Total Data: ", value/len(pcap_merged))

# find outliers (this could potentially help to drill down into the idea
# of abnormal vs normal activity)

# -----------------------------------------------------------------
# cleaning data
# ------------------------------------------------------------------

# drop timestamp and protocol with null value
# (missing data in timestamp and protocol is only 0.7% (0.007))
pcap_merged = pcap_merged[pcap_merged.TIMESTAMP.notnull()]
pcap_merged = pcap_merged[pcap_merged.PROTOCOL.notnull()]

# round timestamp (DO WE WANT TO ROUND IT TO THE SECOND???)

# find the unique protocol values that are being used
uniquePro=pcap_merged.PROTOCOL.unique()
# replace protocol values with protocol labels
pcap_merged['PROTOCOL'].replace(6,'TCP', inplace=True)
pcap_merged['PROTOCOL'].replace(2,'IGMP', inplace=True)
pcap_merged['PROTOCOL'].replace(1,'ICMP', inplace=True)
pcap_merged['PROTOCOL'].replace(17,'UDP', inplace=True)
pcap_merged['PROTOCOL'].replace(547,'UDP', inplace=True)
pcap_merged['PROTOCOL'].replace(5355,'UDP', inplace=True)
pcap_merged['PROTOCOL'].replace(5353,'UDP', inplace=True)


# impute datalength because 16% of data is missing
# -------------------------------------------------------------------
# visualizations
# -------------------------------------------------------------------

# -------------------------------------------------------------------
# analysis
# -------------------------------------------------------------------

