# -*- coding: utf-8 -*-
'''
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
'''

# import libraries
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import time
import datetime
#from imblearn.over_sampling import SMOTE


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

# write to csv
pcap_merged.to_csv('pcap_merged.csv', index=False)

# -------------------------------------------------------------------
# open merged csv file
pcap_merged = pd.read_csv(dir+'pcap_merged.csv', low_memory=False)
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

# drop variables with less than 3% missing data
pcap_merged = pcap_merged[pcap_merged.TIMESTAMP.notnull()]
pcap_merged = pcap_merged[pcap_merged.PROTOCOL.notnull()]
pcap_merged = pcap_merged[pcap_merged.ACKSEQ.notnull()]
pcap_merged = pcap_merged[pcap_merged.SEQ.notnull()]
pcap_merged = pcap_merged[pcap_merged.DSTPORT.notnull()]
pcap_merged = pcap_merged[pcap_merged.SRCMACADDR.notnull()]
pcap_merged = pcap_merged[pcap_merged.SRCPORT.notnull()]
pcap_merged = pcap_merged[pcap_merged.URGENTPTR.notnull()]
pcap_merged = pcap_merged[pcap_merged.WINDOW.notnull()]

# round timestamp (DO WE WANT TO ROUND IT TO THE SECOND???)
pcap_merged['TIMESTAMP'] = pcap_merged['TIMESTAMP'].values.astype('<M8[s]')
main_df['TIMESTAMP'] = main_df['TIMESTAMP'].values.astype('<M8[s]')



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

# fine the min, max, median of data length
# min= 1, max = 1460, median= 1460, mean = 1316.27419
pcap_merged['DATALENGTH'].max()
pcap_merged['DATALENGTH'].min()
pcap_merged['DATALENGTH'].median()
pcap_merged['DATALENGTH'].mean()

# graph distributions
pcap_merged.hist(column='DATALENGTH')
plt.show()

# impute datalength because 16% of data is missing with mode of the column
# the mode is 1400
pcap_merged = pcap_merged.fillna(pcap_merged['DATALENGTH'].value_counts().index[0])


# -------------------------------------------------------------------
# visualizations
# -------------------------------------------------------------------

# graph the labeled MainOutput file to see the frequency of 'Name'
main_df['Name'].value_counts().plot(kind='bar')
plt.show()

# change main_df into long format for graphing
main_melt=pd.melt(main_df, id_vars=["TIMESTAMP", "PROTOCOL", "DATALENGTH", "Name", "Mal"],
                  value_vars=["SRCIP", "DSTIP"],
                  var_name=["IP_TYPE"],
                  value_name="IP_ADDRESS")  

# graph main df by ip address, timestamp, and datalength
main_melt.groupby(['TIMESTAMP','IP_ADDRESS'])['DATALENGTH'].sum().unstack().plot()
plt.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3,
           ncol=2, mode="expand", borderaxespad=0.)
plt.show()

# graph main df by name timestamp and datalength
# the timestamp for the malioucious data is seen on specific days, to get a 
# better view we might need to make three separate graphs for the 3 specific 
# months the attacks were seen
main_melt.groupby(['TIMESTAMP','Name'])['DATALENGTH'].sum().unstack().plot()
plt.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3,
           ncol=2, mode="expand", borderaxespad=0.)
plt.show()

# -------------------------------------------------------------------
# change pcap merged dataframe into format into long format
pcap_melt=pd.melt(pcap_merged, id_vars=["TIMESTAMP", "PROTOCOL", "DATALENGTH"],
                  value_vars=["SRCIP", "DSTIP"],
                  var_name=["IP_TYPE"],
                  value_name="IP_ADDRESS")  

# graph ip addresses data length, timestamp
# use unstack()
pcap_melt.groupby(['TIMESTAMP','IP_ADDRESS'])['DATALENGTH'].sum().unstack().plot()
plt.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3,
           ncol=2, mode="expand", borderaxespad=0.)
plt.show()

# NEED TO UNDERSTAND THE DIFFERENCE BETWEEN COUNT AND SUM IN THESE GRAPHS
pcap_melt.groupby(['TIMESTAMP','IP_ADDRESS'])['DATALENGTH'].count().unstack().plot()
plt.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3,
           ncol=2, mode="expand", borderaxespad=0.)
plt.show()

# -------------------------------------------------------------------

# -------------------------------------------------------------------
# analysis
# -------------------------------------------------------------------

# -------------------------------------------------------------------
# write out merged and cleaned dataframe to csv
# -------------------------------------------------------------------
pcap_merged.to_csv("cleanedPcapMerged.csv")

# -------------------------------------------------------------------