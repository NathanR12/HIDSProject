import os  ## Allows file checks
import time  ## Allows timestamps
import pandas as pd  ## Used to create structured CSV logs


CSV_LOG_FILE = "Suspicious_Alerts.csv"


def Log_Alert(alert_type, source, event="", file_path="", pid="", process_name="", exe_path="", reasons=None, hash_result="", yara_result=""):
    if reasons is None:
        reasons = []

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    alert_data = {
        "Timestamp": timestamp,
        "Alert Type": alert_type,
        "Source": source,
        "Event": event,
        "File Path": file_path,
        "PID": pid,
        "Process Name": process_name,
        "Executable Path": exe_path,
        "Reasons": " | ".join(reasons),
        "Hash Result": hash_result,
        "YARA Result": yara_result
    }

    df = pd.DataFrame([alert_data])

    file_exists = os.path.exists(CSV_LOG_FILE)

    df.to_csv(
        CSV_LOG_FILE,
        mode="a",
        header=not file_exists,
        index=False,
        encoding="utf-8"
    )