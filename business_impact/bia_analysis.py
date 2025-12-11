bia = [
    {"Asset": "EMR System", "Threat Scenario": "Ransomware attack", "Financial Impact": "₱1,000,000", "Operational Impact": "Patient records inaccessible; treatment delay", "Recovery Strategy": "Restore from backup within 6 hours"},
    {"Asset": "Billing System", "Threat Scenario": "Database corruption", "Financial Impact": "₱500,000", "Operational Impact": "Delayed billing and discharges", "Recovery Strategy": "Use backup, verify audit logs"},
    {"Asset": "Power Supply", "Threat Scenario": "Generator failure", "Financial Impact": "₱300,000", "Operational Impact": "Interrupted surgeries, system downtime", "Recovery Strategy": "Maintain spare generator; monthly test runs"},
    {"Asset": "Wi-Fi Network", "Threat Scenario": "Network outage", "Financial Impact": "₱100,000", "Operational Impact": "Slow internal communication, delays in lab work", "Recovery Strategy": "Maintain secondary ISP and failover router"},
    {"Asset": "Staff Database", "Threat Scenario": "Unauthorized access", "Financial Impact": "₱200,000", "Operational Impact": "HR data breach; reputational risk", "Recovery Strategy": "Change credentials, report to DPO within 24 hrs"},
]

def show_bia():
    print("\n--- BUSINESS IMPACT ANALYSIS ---")
    for row in bia:
        print(f"{row['Asset']} | {row['Threat Scenario']} | {row['Financial Impact']} | {row['Operational Impact']} | {row['Recovery Strategy']}")
