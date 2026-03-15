import csv
import psutil
from datetime import datetime

targets = {
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "epicgameslauncher.exe",
    "discord.exe",
}

expected_parents = {
    "msedge.exe": {"msedge.exe", "explorer.exe"},
    "chrome.exe": {"chrome.exe", "explorer.exe"},
    "firefox.exe": {"firefox.exe", "explorer.exe"},
    "steam.exe": {"explorer.exe", "steam.exe"},
    "steamwebhelper.exe": {"steam.exe", "steamwebhelper.exe"},
    "epicgameslauncher.exe": {"explorer.exe", "epicgameslauncher.exe"},
    "discord.exe": {"explorer.exe", "discord.exe"},
}

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

all_file = rf"C:\GameSecurityLab\projects\snapshot_all_{timestamp}.csv"
unusual_file = rf"C:\GameSecurityLab\projects\snapshot_unusual_{timestamp}.csv"
unknown_file = rf"C:\GameSecurityLab\projects\snapshot_unknown_{timestamp}.csv"

rows = []
unusual = []
unknown = []

for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cpu_percent', 'memory_percent']):
    try:
        name = (proc.info['name'] or "").lower()
        if name not in targets:
            continue

        ppid = proc.info['ppid']
        parent_name = "N/A"

        try:
            parent = psutil.Process(ppid)
            parent_name = parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        row = {
            "pid": proc.info['pid'],
            "ppid": ppid,
            "parent_name": parent_name,
            "name": name,
            "cpu_percent": proc.info['cpu_percent'],
            "memory_percent": round(proc.info['memory_percent'], 4),
        }

        rows.append(row)

        parent_name_lower = str(parent_name).lower()
        allowed = expected_parents.get(name, set())

        if parent_name_lower in {"n/a", "", "unknown"}:
            unknown.append(row)
        elif parent_name_lower not in allowed:
            unusual.append(row)

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

fieldnames = ["pid", "ppid", "parent_name", "name", "cpu_percent", "memory_percent"]

with open(all_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

with open(unusual_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(unusual)

with open(unknown_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(unknown)

print(f"All rows: {len(rows)}")
print(f"Unusual rows: {len(unusual)}")
print(f"Unknown rows: {len(unknown)}")
print(f"Saved: {all_file}")
print(f"Saved: {unusual_file}")
print(f"Saved: {unknown_file}")