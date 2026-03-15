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



\## Additional script: Suspicious Process Detector



The repository also includes `suspicious\_process\_detector.py`.



This script checks for suspicious process names such as:



\- `cmd.exe`

\- `powershell.exe`

\- `pwsh.exe`

\- `wscript.exe`

\- `cscript.exe`

\- `rundll32.exe`

\- `mshta.exe`



It flags them when they are spawned by watched parent processes such as:



\- `msedge.exe`

\- `chrome.exe`

\- `firefox.exe`

\- `steam.exe`

\- `steamwebhelper.exe`

\- `epicgameslauncher.exe`

\- `discord.exe`



\### Run



```powershell

python suspicious\_process\_detector.py



\## Additional script: TCP Connection Snapshot



The repository also includes `tcp\_connection\_snapshot.py`.



This script collects live TCP/INET connection data for selected browser and launcher processes.



\### What it records



\- PID

\- process name

\- connection status

\- local address

\- remote address



\### Run



```powershell

python tcp\_connection\_snapshot.py

