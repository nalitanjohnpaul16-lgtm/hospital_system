def show_incident_report(report: dict):
    print("\n--- INCIDENT REPORT ---")
    for key, value in report.items():
        print(f"{key}: {value}")
