import json
import pandas as pd

log_file = "var/log/cowrie/cowrie.json"
data = []

with open(log_file, "r") as file:
    for line in file:
        record = json.loads(line)

        if record.get("eventid") in [
            "cowrie.login.failed",
            "cowrie.login.success",
            "cowrie.command.input"
        ]:
            data.append({
                "timestamp": record.get("timestamp"),
                "src_ip": record.get("src_ip"),
                "event_type": record.get("eventid"),
                "username": record.get("username", "unknown"),
                "command": record.get("input", ""),
                "label": 1  # Intrusion
            })

df = pd.DataFrame(data)
df.to_csv("honeypot_dataset.csv", index=False)

print("Dataset created successfully.")
