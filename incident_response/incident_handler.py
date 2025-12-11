from datetime import datetime
import random
from .incident_report import show_incident_report

_INCIDENT_TEMPLATES = [
    {
        "Incident Type": "Phishing Email",
        "Affected Systems": "Employee email accounts",
        "Actions Taken": "Blocked sender, reset passwords",
        "Status": "Resolved",
    },
    {
        "Incident Type": "Suspicious Login Attempt",
        "Affected Systems": "VPN gateway, user account",
        "Actions Taken": "Account locked, SIEM investigation",
        "Status": "Investigating",
    },
    {
        "Incident Type": "Ransomware Alert",
        "Affected Systems": "File server",
        "Actions Taken": "Isolated host, initiated backup restore",
        "Status": "Containment",
    },
]


def handle_incident():
    print("\n--- INCIDENT HANDLING & REPORTING ---")
    print("Detecting potential incidents...")

    template = random.choice(_INCIDENT_TEMPLATES)
    report = {
        **template,
        "Date & Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    print(f"Incident identified: {report['Incident Type']}.")
    show_incident_report(report)
