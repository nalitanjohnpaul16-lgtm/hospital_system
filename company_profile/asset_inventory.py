assets = [
    {"Asset Name": "Patient Records Database", "Type": "Digital", "Value": "Very High", "Owner": "IT Dept", "Security Classification": "Confidential"},
    {"Asset Name": "Staff Login System", "Type": "Digital", "Value": "High", "Owner": "IT Dept", "Security Classification": "Restricted"},
    {"Asset Name": "Billing & Payment System", "Type": "Digital", "Value": "High", "Owner": "Finance Dept", "Security Classification": "Confidential"},
    {"Asset Name": "Hospital Network", "Type": "Infrastructure", "Value": "Very High", "Owner": "IT Dept", "Security Classification": "Restricted"},
    {"Asset Name": "Admin Workstations", "Type": "Physical", "Value": "Medium", "Owner": "Admin", "Security Classification": "Internal"},
    {"Asset Name": "Doctors’ Mobile App Access", "Type": "Digital", "Value": "High", "Owner": "Medical Staff", "Security Classification": "Restricted"},
    {"Asset Name": "Servers (On-Prem)", "Type": "Physical", "Value": "Very High", "Owner": "IT Dept", "Security Classification": "Restricted"},
    {"Asset Name": "CCTV System", "Type": "Physical", "Value": "Medium", "Owner": "Security Office", "Security Classification": "Internal"},
    {"Asset Name": "Biometric Devices", "Type": "Physical", "Value": "High", "Owner": "IT Dept", "Security Classification": "Restricted"},
    {"Asset Name": "Backup Storage", "Type": "Digital", "Value": "Very High", "Owner": "IT Dept", "Security Classification": "Confidential"},
]

def list_assets():
    print("\n--- ASSET INVENTORY ---")
    for asset in assets:
        print(f"{asset['Asset Name']} | {asset['Type']} | {asset['Value']} | {asset['Owner']} | {asset['Security Classification']}")
