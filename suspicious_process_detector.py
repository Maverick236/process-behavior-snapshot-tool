import csv
import psutil
from datetime import datetime

suspicious_names = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "mshta.exe",
}

watched_parents = {
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "epicgameslauncher.exe",
    "discord.exe",
}

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = rf"C:\GameSecurityLab\github-process-snapshot\suspicious_processes_{timestamp}.csv"

rows = []

for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cpu_percent', 'memory_percent']):
    try:
        name = (proc.info['name'] or "").lower()
        if name not in suspicious_names:
            continue

        ppid = proc.info['ppid']
        parent_name = "N/A"

        try:
            parent = psutil.Process(ppid)
            parent_name = (parent.name() or "N/A").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        if parent_name in watched_parents:
            rows.append({
                "pid": proc.info['pid'],
                "ppid": ppid,
                "parent_name": parent_name,
                "name": name,
                "cpu_percent": proc.info['cpu_percent'],
                "memory_percent": round(proc.info['memory_percent'], 4),
            })

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["pid", "ppid", "parent_name", "name", "cpu_percent", "memory_percent"]
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"Suspicious rows: {len(rows)}")
print(f"Saved: {output_file}")