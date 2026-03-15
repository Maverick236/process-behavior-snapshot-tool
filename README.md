# \# Process Behavior Snapshot Tool

# 

# A Python tool that captures running browser and launcher processes, records parent-child relationships, and separates normal results from unusual and unknown parent process cases.

# 

# \## What it does

# 

# \- Collects a snapshot of selected processes

# \- Records PID, PPID, parent process name, CPU, and memory usage

# \- Exports results to CSV

# \- Separates:

# &#x20; - all matching processes

# &#x20; - unusual parent-child relationships

# &#x20; - unknown parent relationships

# 

# \## Current targets

# 

# \- msedge.exe

# \- chrome.exe

# \- firefox.exe

# \- steam.exe

# \- steamwebhelper.exe

# \- epicgameslauncher.exe

# \- discord.exe

# 

# \## Why it matters

# 

# Parent-child process relationships help show whether behavior looks normal or suspicious. This is a basic detection concept used in security investigations and endpoint monitoring.

# 

# \## Requirements

# 

# \- Python 3

# \- psutil

# 

# \## Install

# 

# ```powershell

# python -m pip install psutil

