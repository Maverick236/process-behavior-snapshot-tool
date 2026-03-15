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

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = rf"C:\GameSecurityLab\github-process-snapshot\tcp_connections_{timestamp}.csv"

rows = []

for conn in psutil.net_connections(kind="inet"):
    try:
        pid = conn.pid
        if not pid:
            continue

        proc = psutil.Process(pid)
        name = (proc.name() or "").lower()

        if name not in targets:
            continue

        local_addr = ""
        remote_addr = ""

        if conn.laddr:
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"

        if conn.raddr:
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"

        rows.append({
            "pid": pid,
            "name": name,
            "status": conn.status,
            "local_address": local_addr,
            "remote_address": remote_addr,
        })

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["pid", "name", "status", "local_address", "remote_address"]
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"Saved {len(rows)} connection rows to {output_file}")