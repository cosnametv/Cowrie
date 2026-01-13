import pandas as pd
import joblib

# Load trained model
model = joblib.load("ids_model.pkl")

# Load honeypot dataset
honeypot_df = pd.read_csv("honeypot_dataset.csv")

# Create NSL-KDD-like feature dataframe
test_data = pd.DataFrame()

test_data["duration"] = 0
test_data["protocol_type"] = 0   # tcp
test_data["service"] = 0         # ssh
test_data["flag"] = 0            # SF
test_data["src_bytes"] = honeypot_df["command"].fillna("").apply(len)
test_data["dst_bytes"] = 0
test_data["land"] = 0
test_data["wrong_fragment"] = 0
test_data["urgent"] = 0
test_data["hot"] = 0
test_data["num_failed_logins"] = 3
test_data["logged_in"] = 0
test_data["num_compromised"] = 0
test_data["root_shell"] = 0
test_data["su_attempted"] = 0
test_data["num_root"] = 0
test_data["num_file_creations"] = 0
test_data["num_shells"] = 0
test_data["num_access_files"] = 0
test_data["num_outbound_cmds"] = 0
test_data["is_host_login"] = 0
test_data["is_guest_login"] = 0
test_data["count"] = 20
test_data["srv_count"] = 20
test_data["serror_rate"] = 0
test_data["srv_serror_rate"] = 0
test_data["rerror_rate"] = 0
test_data["srv_rerror_rate"] = 0
test_data["same_srv_rate"] = 0
test_data["diff_srv_rate"] = 0
test_data["srv_diff_host_rate"] = 0
test_data["dst_host_count"] = 50
test_data["dst_host_srv_count"] = 50
test_data["dst_host_same_srv_rate"] = 0
test_data["dst_host_diff_srv_rate"] = 0
test_data["dst_host_same_src_port_rate"] = 0
test_data["dst_host_srv_diff_host_rate"] = 0
test_data["dst_host_serror_rate"] = 0
test_data["dst_host_srv_serror_rate"] = 0
test_data["dst_host_rerror_rate"] = 0
test_data["dst_host_srv_rerror_rate"] = 0

# Predict using AI model
predictions = model.predict(test_data)

honeypot_df["ml_prediction"] = pd.Series(predictions).map({0: "Normal", 1: "Intrusion"})

# Hybrid IDS (ML + Honeypot rule)
honeypot_df["final_prediction"] = honeypot_df.apply(
    lambda row: "Intrusion"
    if row["ml_prediction"] == "Intrusion" or row["event_type"].startswith("cowrie.")
    else "Normal",
    axis=1
)

# Save results
honeypot_df.to_csv("honeypot_detection_results.csv", index=False)

print("Honeypot intrusion detection completed successfully.")

