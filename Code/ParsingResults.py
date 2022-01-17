#! /usr/bin/env python3
# coding: utf-8

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import string
import math
from bokeh.io import export_png, export_svgs
from bokeh.models import ColumnDataSource, DataTable, TableColumn


# setup vars
DataPerRunDF = pd.DataFrame(columns = ['run nr','setup info', 'pick info', 'reward info'])
setupInfoDF = pd.DataFrame(columns = ['positive reward', 'negative reward', 'number of episodes', 'exploration decay rate'])
pickInfoDF = pd.DataFrame(columns = ['file','episodes','pick type', 'pick nr', 'choice', 'reward', 'success'])
rewardInfoDF = pd.DataFrame(columns = ['runs', 'avg reward'])
EmptysetupInfoDF = pd.DataFrame(columns = ['positive reward', 'negative reward', 'number of episodes', 'exploration decay rate'])
EmptypickInfoDF = pd.DataFrame(columns = ['pick type', 'pick nr', 'choice', 'reward', 'success'])
EmptyrewardInfoDF = pd.DataFrame(columns = ['runs', 'avg reward'])
filenr = 0

folder = "10-15000.001"

# open each file
for filename in os.listdir(folder):
	print(filename)
	with open(os.path.join(folder, filename), 'r') as f:
		filenr += 1
		Lines = f.readlines()
		count = 0 # for the line nrs
		count2 = 0 # to group the pick data by 100
		reward = False
		Qtable = False
		setupInfo = []
		pickInfo = []
		rewardInfo = []

		# read each line
		for line in Lines:
			count += 1

			# if count < line 10: ignore it
			if count > 10 and reward == False and Qtable == False:


				# if one of the lines of a RL episode
				(firstWord, rest) = line.split(maxsplit=1)
				if firstWord in ("pick", "choice:", "reward:", "success:", "state:"):
				
					# create row for pickInfo dataframe
					words = line.split()
					if words[0] == "pick":

						# calculate data per 100 picks
						group = int(count2/100) * 100 + 100
						count2 += 1

						# append relevant data
						pickInfo.append(filenr)
						pickInfo.append(group)
						pickInfo.append(words[1].translate(str.maketrans('', '', string.punctuation)))
						pickInfo.append(words[-1])
					if words[0] == "choice:":
						pickInfo.append(rest.replace('\n', ' ').replace('\r', '').replace('\r\n',''))
					if words[0] =="reward:":
						pickInfo.append(words[-1])
					if words[0] == "success:":
						pickInfo.append(words[-1])
						pickInfoDF.loc[len(pickInfoDF)] = pickInfo
						pickInfo = []

				# if start list of rewards
				elif line.strip() == "********** Average  reward per 10 episodes  **********":
					reward = True
					continue

				#if start Q-table
				elif line.strip() == "********** Q-table **********":
					reward = False
					Qtable = True
					continue

			# process reward data
			if reward:
				# create row for rewardInfo dataframe
				words = line.split()
				runs = words[0].translate(str.maketrans('', '', string.punctuation))
				reward = words[1]
				rewardInfo.append(runs)
				rewardInfo.append(reward)
				rewardInfoDF.loc[len(rewardInfoDF)] = rewardInfo
				rewardInfo = []


			# process Q-table
			if Qtable:
				#rewardInfoDF.loc[len(rewardInfoDF)] = rewardInfo
				DataPerRun = [filenr,setupInfoDF,pickInfoDF,rewardInfoDF]
				DataPerRunDF.loc[len(DataPerRunDF)] = DataPerRun
				Qtable = False
				setupInfoDF = EmptysetupInfoDF
				pickInfoDF = EmptypickInfoDF
				rewardInfoDF = EmptyrewardInfoDF




##### charts and tables #####


#print table to file
def save_df_as_image(df, path):
	source = ColumnDataSource(df)
	df_columns = [df.index.name]
	df_columns.extend(df.columns.values)
	columns_for_table=[]
	for column in df_columns:
		if column == None:
			continue
		else: 
			columns_for_table.append(TableColumn(field=column, title=column))

	data_table = DataTable(source=source, columns=columns_for_table,height_policy="auto",width_policy="auto",index_position=None)
	export_png(data_table, filename = path)


# ratio random/best picks
PickTypePerGroup = pickInfoDF.groupby(['episodes','pick type'])['pick type'].count().unstack('pick type').fillna(0)

# total nr of episodes / 5 because we look at it per 100 episodes and there's 500 of them in total per experiment
df_total = len(pickInfoDF.index)/5

# normalise to 100%
PickTypePerGroup = PickTypePerGroup[PickTypePerGroup.columns[0:]].div(df_total, 0)*100
PickTypePerGroup = PickTypePerGroup.round(2)
PickTypePerGroup = PickTypePerGroup.fillna(0)

# table
save_df_as_image(PickTypePerGroup, folder+"_table_PickTypePerGroup.png")

# chart
PickTypePerGroup[['random', 'best']].plot(kind='bar', stacked=True)
plt.savefig(folder+'_PickTypePerGroup.png')

# random/best succes/failure with check for best choice
PickResultDF = pickInfoDF
PickResultDF.loc[PickResultDF["choice"] == "(4196291, 6295648, 4196171) ", "pick type"] = PickResultDF["pick type"]+"Optimal"

PickResult = PickResultDF.groupby(['episodes','pick type', 'success'])['pick type'].count().fillna(0).reset_index(name="count")
PickResult['picks'] = PickResult['pick type']+PickResult['success']

PickResultPivoted = PickResult.pivot(index="episodes", columns="picks", values="count")
PickResultCharts = pd.DataFrame()
PickResultPivoted['eps']=PickResultPivoted.index

PickResultCharts['episodes'] = PickResultPivoted['eps']
if 'randomFalse' in PickResult.values:
	PickResultCharts['randomFalse'] = PickResultPivoted['randomFalse']
if 'randomTrue' in PickResult.values:
	PickResultCharts['randomTrue'] = PickResultPivoted['randomTrue']
if 'bestTrue' in PickResult.values:
	PickResultCharts['bestTrue'] = PickResultPivoted['bestTrue']
if 'randomOptimalTrue' in PickResult.values:
	PickResultCharts['randomOptimalTrue'] = PickResultPivoted['randomOptimalTrue']
if 'bestOptimalTrue' in PickResult.values:
	PickResultCharts['bestOptimalTrue'] = PickResultPivoted['bestOptimalTrue']
if 'bestFalse' in PickResult.values:
	PickResultCharts['bestFalse'] = PickResultPivoted['bestFalse']

PickResultCharts = PickResultCharts.reset_index(drop=True)
PickResultCharts = PickResultCharts.fillna(0)


# normalise to 100%
PickResultPivotedNormal = PickResultCharts[PickResultCharts.columns[1:]].div(df_total, 0)*100
PickResultPivotedNormal = PickResultPivotedNormal.round(2)
PickResultPivotedNormal = PickResultPivotedNormal.fillna(0)
PickResultPivotedNormal['episodes'] = PickResultCharts['episodes']

# table
save_df_as_image(PickResultPivotedNormal, folder+"_table_PickResultPivotedNormal.png")

# chart
PickResultPivotedNormal.plot(x='episodes',kind='bar', stacked=True)

plt.savefig(folder+'_PickResultBest.png')

