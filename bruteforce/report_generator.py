# bruteforce/report_generator.py
import csv
from .telemetry_db import fetch_events, init_db


def export_csv(run_id: str, out_path: str):
    init_db()

    # Retrieve all telemetry events for this run
    events = fetch_events(run_id)

    # Open CSV file for writing
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Write header row
        writer.writerow([
            "timestamp", "run_id", "username", "password", "remote_ip",
            "status", "http_code", "message", "target_url"
        ])

        # Write each event as a row, using .get() to avoid KeyErrors
        for e in events:
            writer.writerow([
                e.get("timestamp", ""),
                e.get("run_id", ""),
                e.get("username", ""),
                e.get("password", ""),
                e.get("remote_ip", ""),
                e.get("status", ""),
                e.get("http_code", ""),
                e.get("message", ""),
                e.get("target_url", ""),
            ])

    return out_path


if __name__ == "__main__":
    # Allow running this module directly from the command line
    import sys

    # Expect: python -m bruteforce.report_generator <run_id> <out_csv>
    if len(sys.argv) < 3:
        print("Usage: python -m bruteforce.report_generator <run_id> <out_csv>")
        raise SystemExit(1)

    run_id = sys.argv[1]
    out_csv = sys.argv[2]

    # Generate the CSV
    export_csv(run_id, out_csv)

    print("Exported to", out_csv)

