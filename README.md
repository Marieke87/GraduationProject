# GraduationProject
My graduation project on using reinforcement learning to solve ROP chain challenges.

## Report
My report can be found [here](https://github.com/Marieke87/GraduationProject/blob/main/Marieke%20Gijsberts%2C%202415540%20-%20MSc%20Data%20Science%20dissertation.pdf).

## Code
The [Code](Code/) folder shows the code I've used for this project:
 - [ManualROPsolve](Code/ManualROPsolve.py) shows the script used in Chapter 2 Figure 11;
 - [RLcode](Code/RLcode.py) shows the code used to run my reinforcement learning experiments (used with one setup at the time, currently showing the setup for experiment (a));
  - [ParsingResults](Code/ParsingResults.py) shows the code used to parse the results (also used with one setup at the time, currently showing setup for experiment (a)).

## Results
The [Results](Results/) folder is divided up into three subfolders:

### RegisterLogs
The [RegisterLogs](Results/RegisterLogs) folder shows one example of the register data I intented to use as feedback for my agent. It shows all the registers and their contents, for each time a gadget was used. In [this example file](Results/RegisterLogs/logcommands499.txt), 4 gadgets were used, which means that the list rax-gs is documented 4 times. Furter processing of this log file would have been needed to be able to use it as feedback to my agent.

### RLdata
The [RLdata](Results/RLdata) folder shows the raw data of the different experiments I ran, per setup. 

### ParsingResults
The [ParsingResults](Results/ParsingResults) folder shows the charts and tables as used in my thesis:
- [ExplorationExploitation](Results/ParsingResults/ExplorationExploitation) shows the tables and charts that show the ratio of exploration/exploitation in the different setups;
- [PickResults](Results/ParsingResults/PickResults) shows the different picks of each setup.
