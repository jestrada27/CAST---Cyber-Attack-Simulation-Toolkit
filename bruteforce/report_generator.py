# cast/modules/bruteforce/report_generator.py
import sqlite3
import csv
import os

DB = os.environ.get("CAST_BF_TELEMETRY_DB", "./bruteforce_telemetry.db")

def export_csv(run_id, out_path):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT timestamp, username, password, remote_ip, status, http_code, message FROM telemetry WHERE run_id=? ORDER BY id", (run_id,))
    rows = cur.fetchall()
    conn.close()
    with open(out_path, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","username","password","remote_ip","status","http_code","message"])
        writer.writerows(rows)
    return out_path

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: report_generator.py <run_id> <out_csv>")
        exit(1)
    run_id = sys.argv[1]
    out = sys.argv[2]
    export_csv(run_id, out)
    print("Exported to", out)
