import json
import os
import hashlib
import secrets
import datetime
import logging
import threading
from typing import Any, Dict, List
try:
    from db import mysql_client  # type: ignore
except Exception:  # pragma: no cover
    mysql_client = None  # type: ignore
try:
    import mysql.connector  # type: ignore
except Exception:  # pragma: no cover
    mysql = None  # type: ignore

# Optional yagmail for Gmail-based MFA mail sending
try:
    import yagmail  # type: ignore
except Exception:  # pragma: no cover
    yagmail = None  # type: ignore

# Import MySQL CRUD operations
try:
    from utils.mysql_crud import add_mysql_record as _add_mysql_record_impl
    from utils.mysql_crud import update_mysql_record as _update_mysql_record_impl
    from utils.mysql_crud import delete_mysql_record as _delete_mysql_record_impl
except Exception:
    _add_mysql_record_impl = None
    _update_mysql_record_impl = None
    _delete_mysql_record_impl = None

# Import ID manager for ID reuse functionality
try:
    from utils.id_manager import return_id_to_pool
except Exception:
    return_id_to_pool = None

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
ASSETS_FILE = os.path.join(DATA_DIR, "assets.json")
THREATS_FILE = os.path.join(DATA_DIR, "threats.json")
INCIDENTS_FILE = os.path.join(DATA_DIR, "incidents.json")
BIA_FILE = os.path.join(DATA_DIR, "bia.json")
PATIENTS_FILE = os.path.join(DATA_DIR, "patients.json")
KEY_FILE = os.path.join(DATA_DIR, "secret.key")
ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.json")
AUDIT_EVENTS_FILE = os.path.join(DATA_DIR, "audit_events.json")
AUDIT_ARCHIVE_FILE = os.path.join(DATA_DIR, "audit_log_archive.json")
AUDIT_EVENTS_ARCHIVE_FILE = os.path.join(DATA_DIR, "audit_events_archive.json")

# Thread lock for audit events file access
_audit_events_lock = threading.Lock()

# Ephemeral MFA state: username -> {code, expires, attempts, locked_until}
_MFA_CODES: Dict[str, Dict[str, Any]] = {}

def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode()).hexdigest()


def _split_name(full: str) -> tuple[str, str]:
    full = (full or "").strip()
    if not full:
        return "", ""
    parts = full.split()
    if len(parts) == 1:
        return parts[0], ""
    return " ".join(parts[:-1]), parts[-1]

# MySQL helpers
def _mysql_enabled() -> bool:
    try:
        return bool(
            os.environ.get("MYSQL_HOST", "localhost")
            and os.environ.get("MYSQL_DB", "hospital_system")
            and os.environ.get("MYSQL_USER", "root")
            and os.environ.get("MYSQL_PASSWORD", "jjppbbnn")
            and mysql.connector  # type: ignore[attr-defined]
        )
    except Exception:
        return False

def _get_conn():
    return mysql.connector.connect(  # type: ignore[attr-defined]
        host=os.environ.get("MYSQL_HOST", "localhost"),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", "jjppbbnn"),
        database=os.environ.get("MYSQL_DB", "hospital_system"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
    )


def ensure_data_store() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        # seed admin (full access) and viewer accounts
        salt_admin = secrets.token_bytes(16)
        salt_viewer = secrets.token_bytes(16)
        admin = {
            "username": "admin",
            "salt": salt_admin.hex(),
            "hash": _hash_password("Hospital@123", salt_admin),
            "role": "admin",
            "phone": "+10000000000",
            "pin": "123456",
            "biometric_hash": "",
            "email": "",
        }
        viewer = {
            "username": "viewer",
            "salt": salt_viewer.hex(),
            "hash": _hash_password("viewonly", salt_viewer),
            "role": "viewer",
            "phone": "+10000000001",
            "pin": "0000",
            "biometric_hash": "",
        }
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump({"users": [admin, viewer]}, f)
    if not os.path.exists(ASSETS_FILE):
        with open(ASSETS_FILE, "w", encoding="utf-8") as f:
            json.dump({"assets": []}, f)
    if not os.path.exists(THREATS_FILE):
        with open(THREATS_FILE, "w", encoding="utf-8") as f:
            json.dump({"threats": []}, f)
    if not os.path.exists(INCIDENTS_FILE):
        with open(INCIDENTS_FILE, "w", encoding="utf-8") as f:
            json.dump({"incidents": []}, f)
    if not os.path.exists(BIA_FILE):
        with open(BIA_FILE, "w", encoding="utf-8") as f:
            json.dump({"bia": []}, f)
    if not os.path.exists(PATIENTS_FILE):
        with open(PATIENTS_FILE, "w", encoding="utf-8") as f:
            json.dump({"patients": []}, f)
    if not os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump({"accounts": []}, f)
    if not os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, "w", encoding="utf-8") as f:
            json.dump({"logins": []}, f)
    if not os.path.exists(AUDIT_EVENTS_FILE):
        with open(AUDIT_EVENTS_FILE, "w", encoding="utf-8") as f:
            json.dump({"events": []}, f)
    if not os.path.exists(AUDIT_ARCHIVE_FILE):
        with open(AUDIT_ARCHIVE_FILE, "w", encoding="utf-8") as f:
            json.dump({"logins": []}, f)
    if not os.path.exists(AUDIT_EVENTS_ARCHIVE_FILE):
        with open(AUDIT_EVENTS_ARCHIVE_FILE, "w", encoding="utf-8") as f:
            json.dump({"events": []}, f)

    # migrate existing users file to include roles and a viewer account
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {"users": []}

    changed = False
    # ensure roles exist
    for u in data.get("users", []):
        if "role" not in u:
            # default existing users to standard_staff
            u["role"] = "standard_staff"
            changed = True
        if "phone" not in u:
            u["phone"] = ""
            changed = True
        if "pin" not in u:
            u["pin"] = ""
            changed = True
        if "biometric_hash" not in u:
            u["biometric_hash"] = ""
            changed = True
        if "email" not in u:
            u["email"] = ""
            changed = True
        if "country" not in u:
            u["country"] = ""
            changed = True
        if "avatar" not in u:
            u["avatar"] = ""
            changed = True
        if "avatar_ver" not in u:
            u["avatar_ver"] = 0
            changed = True
    # ensure a viewer account exists
    if not any(u.get("username") == "viewer" for u in data.get("users", [])):
        salt_view = secrets.token_bytes(16)
        data.setdefault("users", []).append({
            "username": "viewer",
            "salt": salt_view.hex(),
            "hash": _hash_password("viewonly", salt_view),
            "role": "viewer",
            "phone": "",
            "pin": "",
            "biometric_hash": "",
            "email": "",
            "country": "",
            "avatar": "",
            "avatar_ver": 0,
        })
        changed = True
    if changed:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    # ensure encryption key
    try:
        from cryptography.fernet import Fernet  # type: ignore
        if not os.path.exists(KEY_FILE):
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as kf:
                kf.write(key)
    except Exception:
        pass


def load_json(path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        if isinstance(e, json.JSONDecodeError):
            logger.warning(f"JSON decode error in {path}: {e}. Using default value.")
        return default


def save_json(path: str, data: Dict[str, Any]) -> None:
    # Use atomic write to prevent corruption during concurrent access
    temp_path = path + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        # Atomic rename on Windows
        if os.path.exists(path):
            os.remove(path)
        os.rename(temp_path, path)
    except Exception as e:
        # Clean up temp file if something went wrong
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e


def authenticate(username: str, password: str) -> bool:
    # Try MySQL first if configured (SHA-256 per spec)
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor(dictionary=True)
                cur.execute("SELECT hashed_password FROM users WHERE username=%s", (username,))
                row = cur.fetchone()
                if row and row.get("hashed_password"):
                    calc = hashlib.sha256(password.encode()).hexdigest()
                    return secrets.compare_digest(calc, str(row.get("hashed_password")))
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    # JSON fallback
    db = load_json(USERS_FILE, {"users": []})
    for u in db.get("users", []):
        if u.get("username") == username:
            salt = bytes.fromhex(u.get("salt", ""))
            return secrets.compare_digest(_hash_password(password, salt), u.get("hash", ""))
    return False


def get_user_role(username: str) -> str:
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    """
                    SELECT r.role_name
                    FROM users u JOIN roles r ON u.role_id=r.role_id
                    WHERE u.username=%s
                    """,
                    (username,),
                )
                row = cur.fetchone()
                if row and row.get("role_name"):
                    return str(row.get("role_name"))
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    db = load_json(USERS_FILE, {"users": []})
    for u in db.get("users", []):
        if u.get("username") == username:
            return u.get("role", "editor")
    return "viewer"


def can_edit(username: str) -> bool:
    role = (get_user_role(username) or "").lower()
    # Roles with some editing capability across modules
    editable_roles = {
        "admin",
        "doctor",
        "nurse",
        "inventory",
        "pharmacist",
        "it_security",
        "receptionist",
        "asset_manager",
        "standard_staff",
        "staff",
    }
    return role in editable_roles


def _format_php_amount(value: Any) -> str:
    """Format a value as Php currency string for display.

    Accepts numeric or string inputs like "50000", "50,000", "Php 50,000", "₱5M+"
    and normalizes to "Php 50,000.00" style when possible. On parsing error, it still
    ensures the "Php" prefix is used instead of a raw peso symbol.
    """
    from decimal import Decimal  # type: ignore

    raw = str(value or "").strip()
    if not raw:
        return ""

    # Clean up corrupted peso symbols and other encoding issues
    text = raw
    # Remove corrupted characters like "Ôé▒" which are corrupted peso symbols
    text = text.replace("Ôé▒", "").replace("â‚±", "").replace("â‚¬", "")
    
    # Normalize common prefixes to strip them for numeric parsing
    for prefix in ("Php", "PHP", "php", "P", "₱"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
            break
    
    # Remove thousands separators for parsing
    numeric_candidate = text.replace(",", "")

    try:
        amt = Decimal(numeric_candidate)
        return f"Php {amt:,.2f}"
    except Exception:
        # Fallback: ensure we still present a clean "Php" prefix and strip any corrupted symbols
        cleaned = text.replace("₱", "").replace("Ôé▒", "").replace("â‚±", "").strip()
        return f"Php {cleaned}" if cleaned else "Php 0.00"


def list_records(kind: str, decrypt_patients_db: bool = False, decrypt_clinical: bool = False) -> List[Dict[str, Any]]:
    # MySQL-backed modules (risk & BIA) using hospital_system schema
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor(dictionary=True)
                # Risk & BIA modules
                if kind == "assets":
                    cur.execute("SELECT id, asset_name, type, value, owner, security_classification FROM assets ORDER BY id")
                    rows = cur.fetchall() or []
                    return [
                        {
                            "Asset Name": r["asset_name"],
                            "Type": r["type"],
                            "Value": r["value"],
                            "Owner": r["owner"],
                            "Security Classification": r["security_classification"],
                        }
                        for r in rows
                    ]
                if kind == "threats":
                    cur.execute("SELECT id, threat, vulnerability, likelihood, impact, countermeasure FROM threats ORDER BY id")
                    rows = cur.fetchall() or []
                    return [
                        {
                            "Threat": r["threat"],
                            "Vulnerability": r["vulnerability"],
                            "Likelihood": r["likelihood"],
                            "Impact": r["impact"],
                            "Countermeasure": r["countermeasure"],
                        }
                        for r in rows
                    ]
                if kind == "incidents":
                    cur.execute("SELECT id, incident_type, date_time, affected_systems, actions_taken, status FROM incidents ORDER BY id")
                    rows = cur.fetchall() or []
                    return [
                        {
                            "Incident Type": r["incident_type"],
                            "Date & Time": r["date_time"],
                            "Affected Systems": r["affected_systems"],
                            "Actions Taken": r["actions_taken"],
                            "Status": r["status"],
                        }
                        for r in rows
                    ]
                if kind == "bia":
                    cur.execute("SELECT id, asset, threat_scenario, financial_impact, operational_impact, recovery_strategy FROM bia ORDER BY id")
                    rows = cur.fetchall() or []
                    out: List[Dict[str, Any]] = []
                    for r in rows:
                        raw_fi = r.get("financial_impact", "")
                        # If it looks like a Fernet token, decrypt; otherwise treat as legacy plain value
                        if raw_fi and str(raw_fi).startswith("gAAAA"):
                            try:
                                dec_fi = decrypt_text(str(raw_fi))
                            except Exception:
                                dec_fi = str(raw_fi)
                        else:
                            dec_fi = str(raw_fi or "")
                        out.append(
                            {
                                "Asset": r["asset"],
                                "Threat Scenario": r["threat_scenario"],
                                # Present as Php currency string while the stored value is Fernet-encrypted when written
                                "Financial Impact": _format_php_amount(dec_fi),
                                "Operational Impact": r["operational_impact"],
                                "Recovery Strategy": r["recovery_strategy"],
                            }
                        )
                    return out
                # Clinical modules mapped onto hospital_system schema
                if kind == "doctors":
                    # doctors table: doctor_id, first_name, last_name, specialization, contact_number, contact_number_encrypted
                    cur.execute(
                        """
                        SELECT doctor_id, first_name, last_name, specialization, contact_number, contact_number_encrypted
                        FROM doctors
                        ORDER BY doctor_id
                        """
                    )
                    rows = cur.fetchall() or []
                    out: List[Dict[str, Any]] = []
                    for r in rows:
                        # Handle contact number - use encrypted or decrypted based on request
                        if decrypt_clinical:
                            # Use decrypted contact
                            raw_contact_enc = r.get("contact_number_encrypted", "")
                            if raw_contact_enc and str(raw_contact_enc).startswith("gAAAA"):
                                try:
                                    contact_val = decrypt_text(str(raw_contact_enc))
                                except Exception:
                                    contact_val = str(r.get("contact_number", ""))
                            else:
                                contact_val = str(r.get("contact_number", ""))
                        else:
                            # Use encrypted contact if available
                            raw_contact_enc = r.get("contact_number_encrypted", "")
                            if raw_contact_enc and str(raw_contact_enc).startswith("gAAAA"):
                                contact_val = str(raw_contact_enc)
                            else:
                                contact_val = str(r.get("contact_number", ""))
                        
                        out.append({
                            "ID": r["doctor_id"],
                            "Name": f"{r['first_name']} {r['last_name']}",
                            "Specialty": r["specialization"],
                            "Contact": contact_val,
                        })
                    return out
                if kind == "patients_db":
                    # patients table: patient_id, first_name, last_name, last_name_encrypted, birthdate, gender, contact_number, allergies_encrypted
                    cur.execute(
                        """
                        SELECT patient_id, first_name, last_name, last_name_encrypted, birthdate, gender,
                               contact_number, allergies_encrypted
                        FROM patients
                        ORDER BY patient_id
                        """
                    )
                    rows = cur.fetchall() or []
                    today = datetime.date.today()
                    out: List[Dict[str, Any]] = []
                    for r in rows:
                        birthdate = r.get("birthdate")
                        age_str = ""
                        if isinstance(birthdate, datetime.date):
                            years = today.year - birthdate.year - (
                                (today.month, today.day) < (birthdate.month, birthdate.day)
                            )
                            age_str = str(years)
                        
                        # Handle last name - decrypt if requested
                        raw_last_name = r.get("last_name", "")
                        if decrypt_patients_db and raw_last_name and str(raw_last_name).startswith("gAAAA"):
                            try:
                                last_name_val = decrypt_text(str(raw_last_name))
                            except Exception:
                                last_name_val = str(raw_last_name)
                        else:
                            last_name_val = str(raw_last_name or "")
                        
                        # Handle contact number - decrypt for display
                        raw_contact = r.get("contact_number", "")
                        if raw_contact and str(raw_contact).startswith("gAAAA"):
                            try:
                                contact_val = decrypt_text(str(raw_contact))
                            except Exception:
                                contact_val = str(raw_contact)
                        else:
                            contact_val = str(raw_contact or "")
                        
                        # Handle allergies - decrypt for display
                        raw_allergies = r.get("allergies_encrypted", "")
                        if raw_allergies and str(raw_allergies).startswith("gAAAA"):
                            try:
                                allergies_val = decrypt_text(str(raw_allergies))
                            except Exception:
                                allergies_val = str(raw_allergies)
                        else:
                            allergies_val = str(raw_allergies or "")
                        
                        out.append(
                            {
                                "Patient ID": r["patient_id"],
                                "First Name": r.get("first_name", ""),
                                "Last Name": last_name_val,
                                "Age": age_str,
                                "Gender": r.get("gender", ""),
                                "Contact": contact_val,
                                "Allergies": allergies_val,
                            }
                        )
                    return out
                if kind == "appointments":
                    # appointments joined with patients & doctors for names, including encrypted fields
                    cur.execute(
                        """
                        SELECT a.appointment_id,
                               p.first_name AS patient_first,
                               p.last_name AS patient_last,
                               d.first_name AS doctor_first,
                               d.last_name AS doctor_last,
                               a.enc_patient_id,
                               a.enc_doctor_id,
                               a.appointment_date,
                               a.status,
                               a.status_encrypted
                        FROM appointments a
                        JOIN patients p ON a.patient_id = p.patient_id
                        JOIN doctors d ON a.doctor_id = d.doctor_id
                        ORDER BY a.appointment_id
                        """
                    )
                    rows = cur.fetchall() or []
                    out: List[Dict[str, Any]] = []
                    for r in rows:
                        dt = r.get("appointment_date")
                        if isinstance(dt, (datetime.datetime, datetime.date)):
                            date_str = dt.date().isoformat() if isinstance(dt, datetime.datetime) else dt.isoformat()
                            time_str = dt.time().strftime("%H:%M") if isinstance(dt, datetime.datetime) else ""
                        else:
                            date_str = str(dt) if dt is not None else ""
                            time_str = ""
                        
                        # Handle patient name - use encrypted version if decrypt_clinical is False
                        if decrypt_clinical:
                            # Decrypt patient last name for display
                            patient_last = r.get("patient_last", "")
                            if patient_last and str(patient_last).startswith("gAAAA"):
                                try:
                                    patient_last = decrypt_text(str(patient_last))
                                except Exception:
                                    patient_last = str(patient_last)
                            patient_name = f"{r['patient_first']} {patient_last}"
                        else:
                            # Use encrypted patient name if available
                            enc_patient = r.get("enc_patient_id", "")
                            if enc_patient and str(enc_patient).startswith("gAAAA"):
                                patient_name = str(enc_patient)
                            else:
                                # Fallback to regular name if no encrypted version
                                patient_last = r.get("patient_last", "")
                                if patient_last and str(patient_last).startswith("gAAAA"):
                                    patient_name = f"{r['patient_first']} {patient_last}"
                                else:
                                    patient_name = f"{r['patient_first']} {patient_last}"
                        
                        # Handle doctor name - use encrypted version if decrypt_clinical is False
                        if decrypt_clinical:
                            doctor_name = f"{r['doctor_first']} {r['doctor_last']}"
                        else:
                            # Use encrypted doctor name if available
                            enc_doctor = r.get("enc_doctor_id", "")
                            if enc_doctor and str(enc_doctor).startswith("gAAAA"):
                                doctor_name = str(enc_doctor)
                            else:
                                # Fallback to regular name if no encrypted version
                                doctor_name = f"{r['doctor_first']} {r['doctor_last']}"
                        
                        # Handle status - use encrypted or decrypted based on request
                        if decrypt_clinical:
                            # Use decrypted status
                            raw_status_enc = r.get("status_encrypted", "")
                            if raw_status_enc and str(raw_status_enc).startswith("gAAAA"):
                                try:
                                    status_val = decrypt_text(str(raw_status_enc))
                                except Exception:
                                    status_val = str(r.get("status", ""))
                            else:
                                status_val = str(r.get("status", ""))
                        else:
                            # Use encrypted status if available
                            raw_status_enc = r.get("status_encrypted", "")
                            if raw_status_enc and str(raw_status_enc).startswith("gAAAA"):
                                status_val = str(raw_status_enc)
                            else:
                                status_val = str(r.get("status", ""))
                        
                        out.append(
                            {
                                "Appointment ID": r["appointment_id"],
                                "Patient Name": patient_name,
                                "Doctor Name": doctor_name,
                                "Date": date_str,
                                "Time": time_str,
                                "Status": status_val,
                            }
                        )
                    return out
                if kind == "diagnoses":
                    # diagnoses joined with patients & doctors; use diagnosis_encrypted, notes_encrypted and created_at
                    cur.execute(
                        """
                        SELECT d.diagnosis_id,
                               p.first_name AS patient_first,
                               p.last_name AS patient_last,
                               dc.first_name AS doctor_first,
                               dc.last_name AS doctor_last,
                               d.diagnosis_encrypted,
                               d.notes_encrypted,
                               d.created_at
                        FROM diagnoses d
                        JOIN patients p ON d.patient_id = p.patient_id
                        JOIN doctors dc ON d.doctor_id = dc.doctor_id
                        ORDER BY d.diagnosis_id
                        """
                    )
                    rows = cur.fetchall() or []
                    out: List[Dict[str, Any]] = []
                    for r in rows:
                        created = r.get("created_at")
                        date_str = created.isoformat(sep=" ") if isinstance(created, (datetime.date, datetime.datetime)) else str(created or "")
                        
                        # Decrypt diagnosis if decrypt_clinical is True and it looks like a Fernet token
                        raw_diagnosis = r.get("diagnosis_encrypted", "")
                        if decrypt_clinical and raw_diagnosis and str(raw_diagnosis).startswith("gAAAA"):
                            try:
                                diagnosis_val = decrypt_text(str(raw_diagnosis))
                            except Exception:
                                diagnosis_val = str(raw_diagnosis)
                        else:
                            diagnosis_val = str(raw_diagnosis or "")
                        
                        # Decrypt notes if decrypt_clinical is True and they look like a Fernet token
                        raw_notes = r.get("notes_encrypted", "")
                        if decrypt_clinical and raw_notes and str(raw_notes).startswith("gAAAA"):
                            try:
                                notes_val = decrypt_text(str(raw_notes))
                            except Exception:
                                notes_val = str(raw_notes)
                        else:
                            notes_val = str(raw_notes or "")
                        
                        # Decrypt patient last name for display
                        patient_last = r.get("patient_last", "")
                        if patient_last and str(patient_last).startswith("gAAAA"):
                            try:
                                patient_last = decrypt_text(str(patient_last))
                            except Exception:
                                patient_last = str(patient_last)
                        
                        out.append(
                            {
                                "Diagnosis ID": r["diagnosis_id"],
                                "Patient Name": f"{r['patient_first']} {patient_last}",
                                "Doctor Name": f"{r['doctor_first']} {r['doctor_last']}",
                                "Diagnosis": diagnosis_val,
                                "Date": date_str,
                                "Notes": notes_val,
                            }
                        )
                    return out
                if kind == "prescriptions":
                    # prescriptions joined with patients & doctors; use medications_encrypted, notes_encrypted and created_at
                    cur.execute(
                        """
                        SELECT psc.prescription_id,
                               p.first_name AS patient_first,
                               p.last_name AS patient_last,
                               dc.first_name AS doctor_first,
                               dc.last_name AS doctor_last,
                               psc.medications_encrypted,
                               psc.notes_encrypted,
                               psc.created_at
                        FROM prescriptions psc
                        JOIN patients p ON psc.patient_id = p.patient_id
                        JOIN doctors dc ON psc.doctor_id = dc.doctor_id
                        ORDER BY psc.prescription_id
                        """
                    )
                    rows = cur.fetchall() or []
                    out: List[Dict[str, Any]] = []
                    for r in rows:
                        created = r.get("created_at")
                        date_str = created.isoformat(sep=" ") if isinstance(created, (datetime.date, datetime.datetime)) else str(created or "")
                        
                        # Decrypt medications if decrypt_clinical is True and it looks like a Fernet token
                        raw_medications = r.get("medications_encrypted", "")
                        if decrypt_clinical and raw_medications and str(raw_medications).startswith("gAAAA"):
                            try:
                                medications_val = decrypt_text(str(raw_medications))
                            except Exception:
                                medications_val = str(raw_medications)
                        else:
                            medications_val = str(raw_medications or "")
                        
                        # Decrypt notes if decrypt_clinical is True and they look like a Fernet token
                        raw_notes = r.get("notes_encrypted", "")
                        if decrypt_clinical and raw_notes and str(raw_notes).startswith("gAAAA"):
                            try:
                                notes_val = decrypt_text(str(raw_notes))
                            except Exception:
                                notes_val = str(raw_notes)
                        else:
                            notes_val = str(raw_notes or "")
                        
                        # Decrypt patient last name for display
                        patient_last = r.get("patient_last", "")
                        if patient_last and str(patient_last).startswith("gAAAA"):
                            try:
                                patient_last = decrypt_text(str(patient_last))
                            except Exception:
                                patient_last = str(patient_last)
                        
                        out.append(
                            {
                                "Prescription ID": r["prescription_id"],
                                "Patient Name": f"{r['patient_first']} {patient_last}",
                                "Doctor Name": f"{r['doctor_first']} {r['doctor_last']}",
                                "Medications": medications_val,
                                "Date": date_str,
                                "Notes": notes_val,
                            }
                        )
                    return out
                if kind == "medical_store":
                    # Map to medical_inventory: item_id, item_name, stock_quantity, unit_price, expiration_date, notes, sensitive_flag, created_at
                    cur.execute(
                        """
                        SELECT item_id, item_name, stock_quantity, unit_price, expiration_date, notes, sensitive_flag, created_at
                        FROM medical_inventory
                        ORDER BY item_id
                        """
                    )
                    rows = cur.fetchall() or []
                    out: List[Dict[str, Any]] = []
                    for r in rows:
                        # Format expiration date
                        exp_date = r.get("expiration_date")
                        exp_date_str = exp_date.isoformat() if isinstance(exp_date, (datetime.date, datetime.datetime)) else str(exp_date or "")
                        
                        # Format unit price
                        unit_price = r.get("unit_price", 0.00)
                        unit_price_str = f"{float(unit_price):.2f}" if unit_price is not None else "0.00"
                        
                        # Handle notes - use notes column or fall back to sensitive_flag
                        notes = r.get("notes", "")
                        if not notes and r.get("sensitive_flag"):
                            notes = "Sensitive item - requires special handling"
                        
                        out.append(
                            {
                                "Item ID": r["item_id"],
                                "Name": r.get("item_name", ""),
                                "Quantity": str(r.get("stock_quantity", "")),
                                "Unit Price": unit_price_str,
                                "Expiration Date": exp_date_str,
                                "Notes": notes or "",
                            }
                        )
                    return out
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    # JSON-backed modules
    if kind == "assets":
        return load_json(ASSETS_FILE, {"assets": []})["assets"]
    if kind == "threats":
        return load_json(THREATS_FILE, {"threats": []})["threats"]
    if kind == "incidents":
        return load_json(INCIDENTS_FILE, {"incidents": []})["incidents"]
    if kind == "bia":
        return load_json(BIA_FILE, {"bia": []})["bia"]
    if kind == "patients":
        return load_json(PATIENTS_FILE, {"patients": []})["patients"]
    return []


def save_records(kind: str, items: List[Dict[str, Any]]) -> None:
    # MySQL-backed modules (risk & BIA) using hospital_system schema
    try:
        if _mysql_enabled() and kind in {"assets", "threats", "incidents", "bia"}:
            conn = _get_conn()
            try:
                cur = conn.cursor()
                if kind == "assets":
                    cur.execute("DELETE FROM assets")
                    for it in items:
                        cur.execute(
                            "INSERT INTO assets (asset_name, type, value, owner, security_classification) VALUES (%s,%s,%s,%s,%s)",
                            (
                                it.get("Asset Name"),
                                it.get("Type"),
                                it.get("Value"),
                                it.get("Owner"),
                                it.get("Security Classification"),
                            ),
                        )
                    conn.commit()
                    return
                if kind == "threats":
                    cur.execute("DELETE FROM threats")
                    for it in items:
                        cur.execute(
                            "INSERT INTO threats (threat, vulnerability, likelihood, impact, countermeasure) VALUES (%s,%s,%s,%s,%s)",
                            (
                                it.get("Threat"),
                                it.get("Vulnerability"),
                                it.get("Likelihood"),
                                it.get("Impact"),
                                it.get("Countermeasure"),
                            ),
                        )
                    conn.commit()
                    return
                if kind == "incidents":
                    cur.execute("DELETE FROM incidents")
                    for it in items:
                        cur.execute(
                            "INSERT INTO incidents (incident_type, date_time, affected_systems, actions_taken, status) VALUES (%s,%s,%s,%s,%s)",
                            (
                                it.get("Incident Type"),
                                it.get("Date & Time"),
                                it.get("Affected Systems"),
                                it.get("Actions Taken"),
                                it.get("Status"),
                            ),
                        )
                    conn.commit()
                    return
                if kind == "bia":
                    cur.execute("DELETE FROM bia")
                    for it in items:
                        raw_fi = it.get("Financial Impact")
                        enc_fi = raw_fi
                        # Encrypt financial impact with Fernet unless it already looks encrypted
                        if raw_fi and not str(raw_fi).startswith("gAAAA"):
                            try:
                                enc_fi = encrypt_text(str(raw_fi))
                            except Exception:
                                enc_fi = raw_fi
                        cur.execute(
                            "INSERT INTO bia (asset, threat_scenario, financial_impact, operational_impact, recovery_strategy) VALUES (%s,%s,%s,%s,%s)",
                            (
                                it.get("Asset"),
                                it.get("Threat Scenario"),
                                enc_fi,
                                it.get("Operational Impact"),
                                it.get("Recovery Strategy"),
                            ),
                        )
                    conn.commit()
                    return
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    # JSON-backed modules
    if kind == "assets":
        save_json(ASSETS_FILE, {"assets": items})
    elif kind == "threats":
        save_json(THREATS_FILE, {"threats": items})
    elif kind == "incidents":
        save_json(INCIDENTS_FILE, {"incidents": items})
    elif kind == "bia":
        save_json(BIA_FILE, {"bia": items})
    elif kind == "patients":
        save_json(PATIENTS_FILE, {"patients": items})


def add_mysql_record(kind: str, item: Dict[str, Any], username: str = "system") -> bool:
    """Insert a new clinical record into MySQL for supported kinds.

    Supported kinds: patients_db, appointments, diagnoses, prescriptions, medical_store.
    Returns True on success, False on error or when MySQL is not enabled.
    """
    try:
        if not _mysql_enabled():
            return False
        conn = _get_conn()
        try:
            cur = conn.cursor()
            if kind == "patients_db":
                import datetime
                first_name = item.get("First Name", "")
                last_name = item.get("Last Name", "")
                gender = item.get("Gender") or "Other"
                contact = item.get("Contact") or None
                allergies = item.get("Allergies") or None
                blood_type = item.get("Blood Type") or None
                age_str = item.get("Age", "")
                
                # Calculate birthdate from age
                birthdate = None
                if age_str:
                    try:
                        age = int(age_str)
                        today = datetime.date.today()
                        birthdate = datetime.date(today.year - age, today.month, today.day)
                    except Exception:
                        birthdate = datetime.date(1990, 1, 1)
                else:
                    birthdate = datetime.date(1990, 1, 1)
                
                # Store allergies as Fernet-encrypted text when provided
                if allergies and not str(allergies).startswith("gAAAA"):
                    allergies = encrypt_text(str(allergies))
                
                # Encrypt contact number when provided
                if contact and not str(contact).startswith("gAAAA"):
                    try:
                        contact = encrypt_text(str(contact))
                    except Exception:
                        contact = str(contact)
                
                # Encrypt blood type when provided
                if blood_type and not str(blood_type).startswith("gAAAA"):
                    try:
                        blood_type = encrypt_text(str(blood_type))
                    except Exception:
                        blood_type = str(blood_type)
                
                # Encrypt the last name directly
                if last_name and not str(last_name).startswith("gAAAA"):
                    try:
                        last_name = encrypt_text(str(last_name))
                    except Exception:
                        pass
                
                cur.execute(
                    "INSERT INTO patients (first_name, last_name, birthdate, gender, contact_number, allergies_encrypted, blood_type_encrypted) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (first_name, last_name, birthdate, gender, contact, allergies, blood_type),
                )
            elif kind == "appointments":
                from datetime import datetime as _dt
                # Handle both "Patient Name" (single field) and "Patient First Name"/"Patient Last Name" (separate fields)
                patient_name = item.get("Patient Name", "").strip()
                if patient_name:
                    # Split full name into first and last
                    name_parts = patient_name.split(maxsplit=1)
                    patient_first = name_parts[0] if name_parts else ""
                    patient_last = name_parts[1] if len(name_parts) > 1 else ""
                else:
                    patient_first = item.get("Patient First Name", "").strip()
                    patient_last = item.get("Patient Last Name", "").strip()
                
                doctor_name = item.get("Doctor Name", "").strip()
                date_str = item.get("Date", "").strip()
                time_str = item.get("Time", "").strip()
                status = item.get("Status") or "Scheduled"
                
                if not patient_first or not doctor_name:
                    logger.error(f"Missing patient or doctor name for appointment")
                    return False
                
                cur2 = conn.cursor()
                
                # Find patient by first name, then decrypt and compare last names
                cur2.execute(
                    "SELECT patient_id, last_name FROM patients WHERE first_name=%s",
                    (patient_first,),
                )
                patient_rows = cur2.fetchall()
                prow = None
                
                for pid, encrypted_last in patient_rows:
                    try:
                        # Decrypt the stored last name and compare
                        if encrypted_last and str(encrypted_last).startswith("gAAAA"):
                            decrypted_last = decrypt_text(str(encrypted_last))
                        else:
                            decrypted_last = str(encrypted_last or "")
                        
                        if decrypted_last.lower() == patient_last.lower():
                            prow = (pid,)
                            break
                    except Exception:
                        # If decryption fails, try direct comparison
                        if str(encrypted_last or "").lower() == patient_last.lower():
                            prow = (pid,)
                            break
                
                cur2.execute(
                    "SELECT doctor_id FROM doctors WHERE TRIM(CONCAT(first_name, ' ', last_name))=%s LIMIT 1",
                    (doctor_name,),
                )
                drow = cur2.fetchone()
                
                # If not found, try case-insensitive match
                if not drow:
                    cur2.execute(
                        "SELECT doctor_id FROM doctors WHERE LOWER(TRIM(CONCAT(first_name, ' ', last_name)))=LOWER(%s) LIMIT 1",
                        (doctor_name,),
                    )
                    drow = cur2.fetchone()
                
                cur2.close()
                
                if not prow:
                    logger.error(f"Patient not found: {patient_first} {patient_last}")
                    return False
                if not drow:
                    logger.error(f"Doctor not found: {doctor_name}")
                    return False
                    
                patient_id = int(prow[0])
                doctor_id = int(drow[0])
                
                # Encrypt patient and doctor names for storage
                enc_patient_name = encrypt_text(patient_name) if patient_name else ""
                enc_doctor_name = encrypt_text(doctor_name) if doctor_name else ""
                
                # Encrypt status
                enc_status = encrypt_text(status) if status else ""
                
                # Parse date and time
                dt_val = None
                if date_str:
                    dt_text = f"{date_str} {time_str or '00:00:00'}"
                    try:
                        # Try parsing with time
                        dt_val = _dt.strptime(dt_text, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        try:
                            # Try parsing with HH:MM format
                            dt_val = _dt.strptime(dt_text, "%Y-%m-%d %H:%M")
                        except Exception:
                            try:
                                # Try parsing date only
                                dt_val = _dt.strptime(date_str, "%Y-%m-%d")
                            except Exception:
                                logger.error(f"Failed to parse date/time: {dt_text}")
                                # Use current datetime as fallback
                                dt_val = _dt.now()
                else:
                    # Use current datetime if no date provided
                    dt_val = _dt.now()
                
                cur.execute(
                    "INSERT INTO appointments (doctor_id, patient_id, enc_patient_id, enc_doctor_id, appointment_date, status, status_encrypted) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (doctor_id, patient_id, enc_patient_name, enc_doctor_name, dt_val, status, enc_status),
                )
            elif kind == "diagnoses":
                from datetime import datetime as _dt
                # Handle both "Patient Name" (single field) and "Patient First Name"/"Patient Last Name" (separate fields)
                patient_name = item.get("Patient Name", "").strip()
                if patient_name:
                    # Split full name into first and last
                    name_parts = patient_name.split(maxsplit=1)
                    patient_first = name_parts[0] if name_parts else ""
                    patient_last = name_parts[1] if len(name_parts) > 1 else ""
                else:
                    patient_first = item.get("Patient First Name", "").strip()
                    patient_last = item.get("Patient Last Name", "").strip()
                
                doctor_name = item.get("Doctor Name", "")
                diagnosis_val = item.get("Diagnosis") or ""
                notes_val = item.get("Notes") or ""
                date_str = item.get("Date", "")
                cur2 = conn.cursor()
                
                # Find patient by first name, then decrypt and compare last names
                cur2.execute(
                    "SELECT patient_id, last_name FROM patients WHERE first_name=%s",
                    (patient_first,),
                )
                patient_rows = cur2.fetchall()
                prow = None
                
                for pid, encrypted_last in patient_rows:
                    try:
                        # Decrypt the stored last name and compare
                        if encrypted_last and str(encrypted_last).startswith("gAAAA"):
                            decrypted_last = decrypt_text(str(encrypted_last))
                        else:
                            decrypted_last = str(encrypted_last or "")
                        
                        if decrypted_last.lower() == patient_last.lower():
                            prow = (pid,)
                            break
                    except Exception:
                        # If decryption fails, try direct comparison
                        if str(encrypted_last or "").lower() == patient_last.lower():
                            prow = (pid,)
                            break
                
                cur2.execute(
                    "SELECT doctor_id FROM doctors WHERE TRIM(CONCAT(first_name, ' ', last_name))=%s LIMIT 1",
                    (doctor_name,),
                )
                drow = cur2.fetchone()
                
                # If not found, try case-insensitive match
                if not drow:
                    cur2.execute(
                        "SELECT doctor_id FROM doctors WHERE LOWER(TRIM(CONCAT(first_name, ' ', last_name)))=LOWER(%s) LIMIT 1",
                        (doctor_name,),
                    )
                    drow = cur2.fetchone()
                
                cur2.close()
                if not prow or not drow:
                    return False
                patient_id = int(prow[0])
                doctor_id = int(drow[0])
                # Encrypt diagnosis text with Fernet unless it already looks encrypted
                if diagnosis_val and not str(diagnosis_val).startswith("gAAAA"):
                    diagnosis_val = encrypt_text(str(diagnosis_val))
                # Encrypt notes text with Fernet unless it already looks encrypted
                if notes_val and not str(notes_val).startswith("gAAAA"):
                    notes_val = encrypt_text(str(notes_val))
                created_at = None
                if date_str:
                    try:
                        created_at = _dt.fromisoformat(str(date_str))
                    except Exception:
                        created_at = date_str
                cur.execute(
                    "INSERT INTO diagnoses (patient_id, doctor_id, diagnosis_encrypted, notes_encrypted, created_at) VALUES (%s,%s,%s,%s,%s)",
                    (patient_id, doctor_id, diagnosis_val, notes_val, created_at),
                )
            elif kind == "prescriptions":
                from datetime import datetime as _dt
                # Handle both "Patient Name" (single field) and "Patient First Name"/"Patient Last Name" (separate fields)
                patient_name = item.get("Patient Name", "").strip()
                if patient_name:
                    # Split full name into first and last
                    name_parts = patient_name.split(maxsplit=1)
                    patient_first = name_parts[0] if name_parts else ""
                    patient_last = name_parts[1] if len(name_parts) > 1 else ""
                else:
                    patient_first = item.get("Patient First Name", "").strip()
                    patient_last = item.get("Patient Last Name", "").strip()
                
                doctor_name = item.get("Doctor Name", "")
                meds_val = item.get("Medications") or ""
                notes_val = item.get("Notes") or ""
                date_str = item.get("Date", "")
                cur2 = conn.cursor()
                
                # Find patient by first name, then decrypt and compare last names
                cur2.execute(
                    "SELECT patient_id, last_name FROM patients WHERE first_name=%s",
                    (patient_first,),
                )
                patient_rows = cur2.fetchall()
                prow = None
                
                for pid, encrypted_last in patient_rows:
                    try:
                        # Decrypt the stored last name and compare
                        if encrypted_last and str(encrypted_last).startswith("gAAAA"):
                            decrypted_last = decrypt_text(str(encrypted_last))
                        else:
                            decrypted_last = str(encrypted_last or "")
                        
                        if decrypted_last.lower() == patient_last.lower():
                            prow = (pid,)
                            break
                    except Exception:
                        # If decryption fails, try direct comparison
                        if str(encrypted_last or "").lower() == patient_last.lower():
                            prow = (pid,)
                            break
                
                cur2.execute(
                    "SELECT doctor_id FROM doctors WHERE TRIM(CONCAT(first_name, ' ', last_name))=%s LIMIT 1",
                    (doctor_name,),
                )
                drow = cur2.fetchone()
                
                # If not found, try case-insensitive match
                if not drow:
                    cur2.execute(
                        "SELECT doctor_id FROM doctors WHERE LOWER(TRIM(CONCAT(first_name, ' ', last_name)))=LOWER(%s) LIMIT 1",
                        (doctor_name,),
                    )
                    drow = cur2.fetchone()
                
                cur2.close()
                if not prow or not drow:
                    return False
                patient_id = int(prow[0])
                doctor_id = int(drow[0])
                # Encrypt medications text with Fernet unless it already looks encrypted
                if meds_val and not str(meds_val).startswith("gAAAA"):
                    meds_val = encrypt_text(str(meds_val))
                created_at = None
                if date_str:
                    try:
                        created_at = _dt.fromisoformat(str(date_str))
                    except Exception:
                        created_at = date_str
                if notes_val and not str(notes_val).startswith("gAAAA"):
                    notes_val = encrypt_text(str(notes_val))
                cur.execute(
                    "INSERT INTO prescriptions (patient_id, doctor_id, medications_encrypted, notes_encrypted, created_at) VALUES (%s,%s,%s,%s,%s)",
                    (patient_id, doctor_id, meds_val, notes_val, created_at),
                )
            elif kind == "medical_store":
                from datetime import datetime as _dt
                name = item.get("Name") or ""
                qty_raw = item.get("Quantity") or "0"
                try:
                    qty = int(str(qty_raw))
                except Exception:
                    qty = 0
                
                # Handle unit price
                unit_price_raw = item.get("Unit Price") or "0.00"
                try:
                    unit_price = float(str(unit_price_raw))
                except Exception:
                    unit_price = 0.00
                
                # Handle expiration date
                exp_date_raw = item.get("Expiration Date", "").strip()
                exp_date = None
                if exp_date_raw:
                    try:
                        exp_date = _dt.strptime(exp_date_raw, "%Y-%m-%d").date()
                    except Exception:
                        try:
                            exp_date = _dt.strptime(exp_date_raw, "%m/%d/%Y").date()
                        except Exception:
                            exp_date = None
                
                # Handle notes
                notes = (item.get("Notes") or "").strip()
                sensitive_flag = bool(notes and "sensitive" in notes.lower())
                
                cur.execute(
                    "INSERT INTO medical_inventory (item_name, stock_quantity, unit_price, expiration_date, notes, sensitive_flag) VALUES (%s,%s,%s,%s,%s,%s)",
                    (name, qty, unit_price, exp_date, notes, 1 if sensitive_flag else 0),
                )
            elif kind == "doctors":
                # Parse full name into first and last name
                full_name = item.get("Name", "").strip()
                name_parts = full_name.split(maxsplit=1)
                first_name = name_parts[0] if name_parts else ""
                last_name = name_parts[1] if len(name_parts) > 1 else ""
                specialty = item.get("Specialty", "").strip()
                contact = item.get("Contact", "").strip()
                
                # Encrypt contact information
                contact_encrypted = ""
                if contact and not str(contact).startswith("gAAAA"):
                    contact_encrypted = encrypt_text(str(contact))
                else:
                    contact_encrypted = contact
                
                # Use a default user_id of 1 (admin) for doctors created through the system
                cur.execute(
                    "INSERT INTO doctors (user_id, first_name, last_name, specialization, contact_number, contact_number_encrypted) VALUES (%s,%s,%s,%s,%s,%s)",
                    (1, first_name, last_name, specialty, contact, contact_encrypted),
                )
            else:
                return False
            conn.commit()
            
            # Log audit event
            import datetime
            add_audit_event({
                "kind": kind,
                "action": "add",
                "username": username,
                "timestamp": datetime.datetime.now().isoformat(),
                "details": {"record": item}
            })
            
            return True
        except Exception as e:
            logger.error(f"Error in add_mysql_record for {kind}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            try:
                conn.rollback()
            except Exception:
                pass
            return False
        finally:
            try:
                cur.close()
            except Exception:
                pass
            conn.close()
    except Exception as e:
        logger.error(f"Error connecting to MySQL in add_mysql_record for {kind}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def update_mysql_record(kind: str, db_id: int, item: Dict[str, Any], username: str = "system") -> bool:
    """Update an existing clinical record by primary key in MySQL."""
    try:
        if not _mysql_enabled():
            return False
        conn = _get_conn()
        try:
            cur = conn.cursor()
            if kind == "patients_db":
                first_name = item.get("First Name", "")
                last_name = item.get("Last Name", "")
                gender = item.get("Gender") or "Other"
                contact = item.get("Contact") or None
                allergies = item.get("Allergies") or None
                age_str = item.get("Age", "")
                
                # Calculate birthdate from age
                import datetime
                birthdate = None
                if age_str:
                    try:
                        age = int(age_str)
                        today = datetime.date.today()
                        birthdate = datetime.date(today.year - age, today.month, today.day)
                    except Exception:
                        # Default to a reasonable birthdate if age is invalid
                        birthdate = datetime.date(1990, 1, 1)
                else:
                    birthdate = datetime.date(1990, 1, 1)
                
                # Ensure allergies remain Fernet-encrypted in the database
                if allergies and not str(allergies).startswith("gAAAA"):
                    allergies = encrypt_text(str(allergies))
                
                # Ensure contact number is stored encrypted
                if contact and not str(contact).startswith("gAAAA"):
                    try:
                        contact = encrypt_text(str(contact))
                    except Exception:
                        contact = str(contact)
                
                # Keep last_name as plain text, create encrypted version separately
                last_name_encrypted = None
                if last_name:
                    # If last_name is already encrypted (shouldn't be), decrypt it first
                    if str(last_name).startswith("gAAAA"):
                        try:
                            last_name = decrypt_text(str(last_name))
                        except Exception:
                            pass
                    # Create encrypted version
                    try:
                        last_name_encrypted = encrypt_text(str(last_name))
                    except Exception:
                        last_name_encrypted = last_name
                
                cur.execute(
                    "UPDATE patients SET first_name=%s, last_name=%s, last_name_encrypted=%s, birthdate=%s, gender=%s, contact_number=%s, allergies_encrypted=%s WHERE patient_id=%s",
                    (first_name, last_name, last_name_encrypted, birthdate, gender, contact, allergies, db_id),
                )
            elif kind == "appointments":
                from datetime import datetime as _dt
                patient_name = item.get("Patient Name", "").strip()
                doctor_name = item.get("Doctor Name", "").strip()
                date_str = item.get("Date", "").strip()
                time_str = item.get("Time", "").strip()
                status = item.get("Status") or "Scheduled"
                
                if not patient_name or not doctor_name:
                    logger.error(f"Missing patient or doctor name for appointment update")
                    return False
                
                # Split patient name into first and last
                name_parts = patient_name.split(maxsplit=1)
                patient_first = name_parts[0] if name_parts else ""
                patient_last = name_parts[1] if len(name_parts) > 1 else ""
                
                cur2 = conn.cursor()
                
                # Find patient by first name, then decrypt and compare last names
                cur2.execute(
                    "SELECT patient_id, last_name FROM patients WHERE first_name=%s",
                    (patient_first,),
                )
                patient_rows = cur2.fetchall()
                prow = None
                
                for pid, encrypted_last in patient_rows:
                    try:
                        # Decrypt the stored last name and compare
                        if encrypted_last and str(encrypted_last).startswith("gAAAA"):
                            decrypted_last = decrypt_text(str(encrypted_last))
                        else:
                            decrypted_last = str(encrypted_last or "")
                        
                        if decrypted_last.lower() == patient_last.lower():
                            prow = (pid,)
                            break
                    except Exception:
                        # If decryption fails, try direct comparison
                        if str(encrypted_last or "").lower() == patient_last.lower():
                            prow = (pid,)
                            break
                
                cur2.execute(
                    "SELECT doctor_id FROM doctors WHERE TRIM(CONCAT(first_name, ' ', last_name))=%s LIMIT 1",
                    (doctor_name,),
                )
                drow = cur2.fetchone()
                
                # If not found, try case-insensitive match
                if not drow:
                    cur2.execute(
                        "SELECT doctor_id FROM doctors WHERE LOWER(TRIM(CONCAT(first_name, ' ', last_name)))=LOWER(%s) LIMIT 1",
                        (doctor_name,),
                    )
                    drow = cur2.fetchone()
                
                cur2.close()
                
                if not prow:
                    logger.error(f"Patient not found for update: {patient_name}")
                    return False
                if not drow:
                    logger.error(f"Doctor not found for update: {doctor_name}")
                    return False
                    
                patient_id = int(prow[0])
                doctor_id = int(drow[0])
                
                # Parse date and time
                dt_val = None
                if date_str:
                    dt_text = f"{date_str} {time_str or '00:00:00'}"
                    try:
                        # Try parsing with time
                        dt_val = _dt.strptime(dt_text, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        try:
                            # Try parsing with HH:MM format
                            dt_val = _dt.strptime(dt_text, "%Y-%m-%d %H:%M")
                        except Exception:
                            try:
                                # Try parsing date only
                                dt_val = _dt.strptime(date_str, "%Y-%m-%d")
                            except Exception:
                                logger.error(f"Failed to parse date/time for update: {dt_text}")
                                # Use current datetime as fallback
                                dt_val = _dt.now()
                else:
                    # Use current datetime if no date provided
                    dt_val = _dt.now()
                
                # Encrypt status for consistency with creation
                enc_status = encrypt_text(status) if status else ""
                
                logger.info(f"Updating appointment {db_id} with status: {status}")
                cur.execute(
                    "UPDATE appointments SET doctor_id=%s, patient_id=%s, appointment_date=%s, status=%s, status_encrypted=%s WHERE appointment_id=%s",
                    (doctor_id, patient_id, dt_val, status, enc_status, db_id),
                )
                logger.info(f"Successfully updated appointment {db_id} status to: {status} (encrypted: {enc_status[:20]}...)")
            elif kind == "diagnoses":
                from datetime import datetime as _dt
                diagnosis_val = item.get("Diagnosis") or ""
                notes_val = item.get("Notes") or ""
                date_str = item.get("Date", "")
                # Encrypt diagnosis text with Fernet unless it already looks encrypted
                if diagnosis_val and not str(diagnosis_val).startswith("gAAAA"):
                    diagnosis_val = encrypt_text(str(diagnosis_val))
                if notes_val and not str(notes_val).startswith("gAAAA"):
                    notes_val = encrypt_text(str(notes_val))
                created_at = None
                if date_str:
                    try:
                        created_at = _dt.fromisoformat(str(date_str))
                    except Exception:
                        created_at = date_str
                cur.execute(
                    "UPDATE diagnoses SET diagnosis_encrypted=%s, notes_encrypted=%s, created_at=%s WHERE diagnosis_id=%s",
                    (diagnosis_val, notes_val, created_at, db_id),
                )
            elif kind == "prescriptions":
                from datetime import datetime as _dt
                meds_val = item.get("Medications") or ""
                notes_val = item.get("Notes") or ""
                date_str = item.get("Date", "")
                # Encrypt medications text with Fernet unless it already looks encrypted
                if meds_val and not str(meds_val).startswith("gAAAA"):
                    meds_val = encrypt_text(str(meds_val))
                if notes_val and not str(notes_val).startswith("gAAAA"):
                    notes_val = encrypt_text(str(notes_val))
                created_at = None
                if date_str:
                    try:
                        created_at = _dt.fromisoformat(str(date_str))
                    except Exception:
                        created_at = date_str
                cur.execute(
                    "UPDATE prescriptions SET medications_encrypted=%s, notes_encrypted=%s, created_at=%s WHERE prescription_id=%s",
                    (meds_val, notes_val, created_at, db_id),
                )
            elif kind == "medical_store":
                from datetime import datetime as _dt
                name = item.get("Name") or ""
                qty_raw = item.get("Quantity") or "0"
                try:
                    qty = int(str(qty_raw))
                except Exception:
                    qty = 0
                
                # Handle unit price
                unit_price_raw = item.get("Unit Price") or "0.00"
                try:
                    unit_price = float(str(unit_price_raw))
                except Exception:
                    unit_price = 0.00
                
                # Handle expiration date
                exp_date_raw = item.get("Expiration Date", "").strip()
                exp_date = None
                if exp_date_raw:
                    try:
                        exp_date = _dt.strptime(exp_date_raw, "%Y-%m-%d").date()
                    except Exception:
                        try:
                            exp_date = _dt.strptime(exp_date_raw, "%m/%d/%Y").date()
                        except Exception:
                            exp_date = None
                
                # Handle notes
                notes = (item.get("Notes") or "").strip()
                sensitive_flag = bool(notes and "sensitive" in notes.lower())
                
                cur.execute(
                    "UPDATE medical_inventory SET item_name=%s, stock_quantity=%s, unit_price=%s, expiration_date=%s, notes=%s, sensitive_flag=%s WHERE item_id=%s",
                    (name, qty, unit_price, exp_date, notes, 1 if sensitive_flag else 0, db_id),
                )
            elif kind == "doctors":
                # Parse full name into first and last name
                full_name = item.get("Name", "").strip()
                name_parts = full_name.split(maxsplit=1)
                first_name = name_parts[0] if name_parts else ""
                last_name = name_parts[1] if len(name_parts) > 1 else ""
                specialty = item.get("Specialty", "").strip()
                contact = item.get("Contact", "").strip()
                
                cur.execute(
                    "UPDATE doctors SET first_name=%s, last_name=%s, specialization=%s, contact_number=%s WHERE doctor_id=%s",
                    (first_name, last_name, specialty, contact, db_id),
                )
            else:
                logger.error(f"Unknown kind for update_mysql_record: {kind}")
                return False
            conn.commit()
            
            # Log audit event
            import datetime
            add_audit_event({
                "kind": kind,
                "action": "update",
                "username": username,
                "timestamp": datetime.datetime.now().isoformat(),
                "details": {"record_id": db_id, "record": item}
            })
            
            return True
        except Exception as e:
            logger.error(f"Error updating MySQL record for {kind} (ID={db_id}): {e}")
            import traceback
            logger.error(traceback.format_exc())
            try:
                conn.rollback()
            except Exception:
                pass
            return False
        finally:
            try:
                cur.close()
            except Exception:
                pass
            conn.close()
    except Exception as e:
        logger.error(f"Error connecting to MySQL for update {kind}: {e}")
        return False


def delete_mysql_record(kind: str, db_id: int, username: str = "system") -> bool:
    """Delete a clinical record by primary key in MySQL and return ID to pool for reuse."""
    try:
        if not _mysql_enabled():
            return False
        conn = _get_conn()
        try:
            cur = conn.cursor()
            if kind == "patients_db":
                cur.execute("DELETE FROM patients WHERE patient_id=%s", (db_id,))
            elif kind == "appointments":
                cur.execute("DELETE FROM appointments WHERE appointment_id=%s", (db_id,))
            elif kind == "diagnoses":
                cur.execute("DELETE FROM diagnoses WHERE diagnosis_id=%s", (db_id,))
            elif kind == "prescriptions":
                cur.execute("DELETE FROM prescriptions WHERE prescription_id=%s", (db_id,))
            elif kind == "medical_store":
                cur.execute("DELETE FROM medical_inventory WHERE item_id=%s", (db_id,))
            elif kind == "doctors":
                cur.execute("DELETE FROM doctors WHERE doctor_id=%s", (db_id,))
            else:
                logger.error(f"Unknown kind for delete_mysql_record: {kind}")
                return False
            conn.commit()
            
            # Return the deleted ID to the pool for reuse
            if return_id_to_pool:
                try:
                    return_id_to_pool(kind, db_id)
                    logger.info(f"Returned ID {db_id} to pool for {kind}")
                except Exception as e:
                    logger.warning(f"Failed to return ID to pool: {e}")
            
            # Log audit event
            import datetime
            add_audit_event({
                "kind": kind,
                "action": "delete",
                "username": username,
                "timestamp": datetime.datetime.now().isoformat(),
                "details": {"record_id": db_id}
            })
            
            return True
        except Exception as e:
            logger.error(f"Error in delete_mysql_record for {kind} (ID={db_id}): {e}")
            import traceback
            logger.error(traceback.format_exc())
            try:
                conn.rollback()
            except Exception:
                pass
            return False
        finally:
            try:
                cur.close()
            except Exception:
                pass
            conn.close()
    except Exception as e:
        logger.error(f"Error connecting to MySQL in delete_mysql_record for {kind}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


# User management helpers
def _load_users() -> Dict[str, Any]:
    return load_json(USERS_FILE, {"users": []})


def _save_users(data: Dict[str, Any]) -> None:
    save_json(USERS_FILE, data)


def get_user(username: str) -> Dict[str, Any]:
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    """
                    SELECT u.username, u.email, u.phone, u.pin_code, r.role_name AS role
                    FROM users u JOIN roles r ON u.role_id=r.role_id
                    WHERE u.username=%s
                    """,
                    (username,),
                )
                row = cur.fetchone() or {}
                return {
                    "username": row.get("username", ""),
                    "email": row.get("email", ""),
                    "phone": row.get("phone", ""),
                    "pin": row.get("pin_code", ""),
                    "role": row.get("role", "viewer"),
                } if row else {}
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    db = _load_users()
    for u in db.get("users", []):
        if u.get("username") == username:
            return u
    return {}


def create_user(username: str, password: str, phone: str, pin: str, role: str = "viewer", biometric_hash: str = "", email: str = "", country: str = "", specialty: str = "") -> bool:
    # Try MySQL path
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor()
                # resolve role_id
                cur.execute("SELECT role_id FROM roles WHERE role_name=%s", (role or "viewer",))
                r = cur.fetchone()
                role_id = int(r[0]) if r else 1
                hpw = hashlib.sha256(password.encode()).hexdigest()
                cur.execute(
                    "INSERT INTO users (username, hashed_password, role_id, email, phone, pin_code) VALUES (%s,%s,%s,%s,%s,%s)",
                    (username, hpw, role_id, email, phone, pin),
                )
                user_id = cur.lastrowid
                # If this is a doctor account, also create a doctors table entry
                if (role or "").lower() == "doctor":
                    first_name = username
                    last_name = ""
                    cur.execute(
                        """
                        INSERT INTO doctors (user_id, first_name, last_name, specialization,
                                            contact_number, email, pin_code, biometric_face_data,
                                            biometric_fingerprint_data)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (user_id, first_name, last_name, specialty, phone, email, pin, None, None),
                    )
                conn.commit()
                return True
            except Exception:
                conn.rollback()
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    # JSON fallback
    db = _load_users()
    if any(u.get("username") == username for u in db.get("users", [])):
        return False
    # Allow duplicate emails in demo
    # Allow duplicate phone numbers in demo
    salt = secrets.token_bytes(16)
    user = {
        "username": username,
        "salt": salt.hex(),
        "hash": _hash_password(password, salt),
        "role": role,
        "phone": phone,
        "pin": pin,
        "biometric_hash": biometric_hash,
        "email": email,
        "country": country,
        "specialty": specialty,
    }
    db.setdefault("users", []).append(user)
    _save_users(db)
    return True


def list_users(limit: int = 50) -> List[Dict[str, Any]]:
    """Return a list of system users for dashboard, preferring MySQL when enabled."""
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    """
                    SELECT u.username, u.email, u.phone, r.role_name AS role
                    FROM users u JOIN roles r ON u.role_id=r.role_id
                    ORDER BY u.username ASC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall() or []
                out: List[Dict[str, Any]] = []
                for r in rows:
                    out.append({
                        "username": r.get("username", ""),
                        "email": r.get("email", ""),
                        "phone": r.get("phone", ""),
                        "role": r.get("role", ""),
                    })
                return out
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    # JSON fallback
    db = _load_users()
    users = []
    for u in db.get("users", []):
        users.append({
            "username": u.get("username", ""),
            "email": u.get("email", ""),
            "phone": u.get("phone", ""),
            "role": u.get("role", ""),
        })
    return users[:limit]


def set_password(username: str, new_password: str) -> bool:
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor()
                hpw = hashlib.sha256(new_password.encode()).hexdigest()
                cur.execute("UPDATE users SET hashed_password=%s WHERE username=%s", (hpw, username))
                conn.commit()
                return cur.rowcount > 0
            except Exception:
                conn.rollback()
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    db = _load_users()
    for u in db.get("users", []):
        if u.get("username") == username:
            salt = secrets.token_bytes(16)
            u["salt"] = salt.hex()
            u["hash"] = _hash_password(new_password, salt)
            _save_users(db)
            return True
    return False


def delete_user(username: str) -> bool:
    """Delete a user account from MySQL or JSON fallback.

    For MySQL, also removes any linked doctor record. Returns True on success.
    """
    # MySQL path
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor()
                # Find user_id first so we can clean up related doctor row
                cur.execute("SELECT user_id FROM users WHERE username=%s", (username,))
                row = cur.fetchone()
                if not row:
                    return False
                user_id = int(row[0])
                # Delete any linked doctor profile
                cur.execute("DELETE FROM doctors WHERE user_id=%s", (user_id,))
                # Delete the user account itself
                cur.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
                conn.commit()
                return True
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass

    # JSON fallback
    db = _load_users()
    before = len(db.get("users", []))
    db["users"] = [u for u in db.get("users", []) if u.get("username") != username]
    if len(db.get("users", [])) < before:
        _save_users(db)
        return True
    return False


def ban_user(username: str, banned_by: str) -> bool:
    """Ban a user account. Only admins can ban users.
    
    This marks the user as banned and prevents them from logging in.
    Returns True on success.
    """
    # Check if the acting user is an admin
    acting_user = get_user(banned_by)
    if not acting_user or (acting_user.get("role", "").lower() != "admin"):
        return False
    
    # Cannot ban yourself
    if username == banned_by:
        return False
    
    # MySQL path
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor()
                # Check if user exists
                cur.execute("SELECT user_id FROM users WHERE username=%s", (username,))
                row = cur.fetchone()
                if not row:
                    return False
                
                # Add a banned flag column if it doesn't exist (for future use)
                # For now, we'll just delete the user as a ban mechanism
                user_id = int(row[0])
                cur.execute("DELETE FROM doctors WHERE user_id=%s", (user_id,))
                cur.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
                conn.commit()
                return True
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    
    # JSON fallback - delete the user
    db = _load_users()
    before = len(db.get("users", []))
    db["users"] = [u for u in db.get("users", []) if u.get("username") != username]
    if len(db.get("users", [])) < before:
        _save_users(db)
        return True
    return False


def verify_pin(username: str, pin: str) -> bool:
    u = get_user(username)
    return bool(u) and str(u.get("pin", "")) == str(pin)


def set_biometric_hash(username: str, bio_hash: str) -> bool:
    db = _load_users()
    for u in db.get("users", []):
        if u.get("username") == username:
            u["biometric_hash"] = bio_hash
            _save_users(db)
            return True
    return False


def verify_biometric_hash(username: str, bio_hash: str) -> bool:
    u = get_user(username)
    return bool(u) and u.get("biometric_hash", "") and u.get("biometric_hash") == bio_hash


# MFA helpers (demo only)
def generate_mfa_code(username: str) -> str:
    import time
    now = int(time.time())
    code = f"{secrets.randbelow(1000000):06d}"
    st = _MFA_CODES.get(username, {"attempts": 0, "locked_until": 0})
    st.update({"code": code, "expires": now + 300})
    _MFA_CODES[username] = st
    return code


def verify_mfa_code(username: str, code: str) -> bool:
    import time
    now = int(time.time())
    st = _MFA_CODES.get(username) or {"attempts": 0, "locked_until": 0}
    if st.get("locked_until", 0) > now:
        return False
    valid = bool(st.get("code")) and st.get("code") == code and st.get("expires", 0) >= now
    if valid:
        st["attempts"] = 0
        _MFA_CODES[username] = st
        return True
    st["attempts"] = int(st.get("attempts", 0)) + 1
    if st["attempts"] >= 5:
        st["locked_until"] = now + 60
        st["attempts"] = 0
    _MFA_CODES[username] = st
    return False


def _send_email_via_yagmail(to_email: str, subject: str, body: str) -> bool:
    if yagmail is None:
        return False
    gmail_user = os.environ.get("GMAIL_USER", "").strip()
    gmail_app_pw = os.environ.get("GMAIL_APP_PASSWORD", "").strip()
    if not (gmail_user and gmail_app_pw and to_email):
        return False
    try:
        yag = yagmail.SMTP(gmail_user, gmail_app_pw)
        yag.send(to=to_email, subject=subject, contents=body)
        return True
    except Exception:
        return False


def _send_email_via_smtp_direct(to_email: str, subject: str, body: str) -> bool:
    import smtplib
    from email.message import EmailMessage
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "0") or 0)
    user = os.environ.get("SMTP_USER", "").strip()
    pwd = os.environ.get("SMTP_PASS", "").strip()
    sender = os.environ.get("SMTP_FROM", user).strip()
    if not (to_email and host and port and user and pwd and sender):
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls()
            s.login(user, pwd)
            s.send_message(msg)
        return True
    except Exception:
        return False


def send_mfa_code(username: str, code: str) -> bool:
    """Send code to the stored email for username.
    Prefers Gmail via yagmail when configured, falls back to direct SMTP.
    """
    u = get_user(username)
    to_email = (u or {}).get("email", "").strip()
    if not to_email:
        return False
    subject = "Your MFA Code"
    body = f"Your verification code is: {code}"
    # Try yagmail first
    if _send_email_via_yagmail(to_email, subject, body):
        return True
    # Fallback to SMTP
    return _send_email_via_smtp_direct(to_email, subject, body)


def send_mfa_code_to(target_email: str, code: str) -> bool:
    """Send code to an explicit email (e.g., user-provided during MFA contact)."""
    target_email = (target_email or "").strip()
    if not target_email:
        return False
    subject = "Your MFA Code"
    body = f"Your verification code is: {code}"
    if _send_email_via_yagmail(target_email, subject, body):
        return True
    return _send_email_via_smtp_direct(target_email, subject, body)


# Optional SMS via Twilio
def send_sms_code(username: str, code: str) -> bool:
    u = get_user(username)
    to_phone = (u or {}).get("phone", "").strip()
    sid = os.environ.get("TWILIO_SID", "").strip()
    token = os.environ.get("TWILIO_TOKEN", "").strip()
    from_num = os.environ.get("TWILIO_FROM", "").strip()
    if not (to_phone and sid and token and from_num):
        return False
    try:
        # simple REST call without twilio-sdk to avoid dependency
        import base64, json as _json, urllib.request, urllib.parse
        data = urllib.parse.urlencode({
            'To': to_phone,
            'From': from_num,
            'Body': f'Your verification code is: {code}'
        }).encode()
        req = urllib.request.Request(
            url=f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
            data=data
        )
        auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
        req.add_header('Authorization', f'Basic {auth}')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


# Validators & helpers
def is_valid_username(username: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username))


def is_valid_phone(phone: str) -> bool:
    import re
    return bool(re.fullmatch(r"\+?\d{8,15}", phone))


def is_valid_email(email: str) -> bool:
    import re
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


def is_valid_password(password: str) -> bool:
    """
    Validate password requirements:
    - At least 8 characters
    - At least 1 number
    - At least 1 capital letter
    - At least 1 symbol
    """
    import re
    if len(password) < 8:
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True


def update_user(username: str, updates: Dict[str, Any]) -> bool:
    try:
        if _mysql_enabled():
            fields = []
            params: List[Any] = []  # type: ignore
            if updates.get("email") is not None:
                fields.append("email=%s"); params.append(updates.get("email"))
            if updates.get("phone") is not None:
                fields.append("phone=%s"); params.append(updates.get("phone"))
            if updates.get("pin") is not None:
                fields.append("pin_code=%s"); params.append(updates.get("pin"))
            if not fields:
                return True
            params.append(username)
            conn = _get_conn()
            try:
                cur = conn.cursor()
                sql = f"UPDATE users SET {', '.join(fields)} WHERE username=%s"
                cur.execute(sql, tuple(params))
                conn.commit()
                return cur.rowcount > 0
            except Exception:
                conn.rollback()
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    db = _load_users()
    for u in db.get("users", []):
        if u.get("username") == username:
            # Demo mode: allow duplicate email/phone values across users
            u.update({k: v for k, v in updates.items() if v is not None})
            _save_users(db)
            return True
    return False


def remember_account(username: str, saved_password: str = "") -> None:
    data = load_json(ACCOUNTS_FILE, {"accounts": []})
    accs = data.get("accounts", [])
    # normalize to dicts
    norm = []
    for a in accs:
        if isinstance(a, str):
            norm.append({"username": a, "saved_password": ""})
        else:
            norm.append({"username": a.get("username"), "saved_password": a.get("saved_password", "")})
    if not any(x.get("username") == username for x in norm):
        norm.append({"username": username, "saved_password": saved_password})
    else:
        for x in norm:
            if x.get("username") == username and saved_password:
                x["saved_password"] = saved_password
    data["accounts"] = norm
    save_json(ACCOUNTS_FILE, data)


def list_accounts() -> List[Dict[str, Any]]:
    accs = load_json(ACCOUNTS_FILE, {"accounts": []}).get("accounts", [])
    out: List[Dict[str, Any]] = []
    for a in accs:
        if isinstance(a, str):
            out.append({"username": a, "saved_password": ""})
        else:
            out.append({"username": a.get("username"), "saved_password": a.get("saved_password", "")})
    return out


def remove_account(username: str) -> None:
    data = load_json(ACCOUNTS_FILE, {"accounts": []})
    acc = []
    for a in data.get("accounts", []):
        if isinstance(a, str):
            if a != username:
                acc.append(a)
        else:
            if a.get("username") != username:
                acc.append(a)
    data["accounts"] = acc
    save_json(ACCOUNTS_FILE, data)


def remove_saved_password(username: str) -> None:
    data = load_json(ACCOUNTS_FILE, {"accounts": []})
    changed = False
    for a in data.get("accounts", []):
        if isinstance(a, dict) and a.get("username") == username:
            if a.get("saved_password"):
                a["saved_password"] = ""
                changed = True
    if changed:
        save_json(ACCOUNTS_FILE, data)


# Encryption helpers for patient data
def _get_fernet():
    try:
        from cryptography.fernet import Fernet  # type: ignore
        with open(KEY_FILE, "rb") as kf:
            key = kf.read()
        return Fernet(key)
    except Exception:
        return None


def encrypt_text(plain: str) -> str:
    f = _get_fernet()
    if not f:
        return plain
    return f.encrypt(plain.encode()).decode()


def decrypt_text(token: str) -> str:
    f = _get_fernet()
    if not f:
        return token
    try:
        return f.decrypt(token.encode()).decode()
    except Exception:
        return ""


def add_audit_login(entry: Dict[str, Any]) -> None:
    # Try MySQL first if configured
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO audit_logins (username, timestamp, ip, user_agent) VALUES (%s,%s,%s,%s)",
                    (
                        entry.get("username"),
                        entry.get("timestamp"),
                        entry.get("ip"),
                        entry.get("user_agent"),
                    ),
                )
                conn.commit()
                return
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    # JSON fallback (also enrich with role/email/phone for reporting)
    u = get_user(entry.get("username", ""))
    if u:
        entry = dict(entry)
        entry.update({
            "role": u.get("role", ""),
            "email": u.get("email", ""),
            "phone": u.get("phone", ""),
        })
    data = load_json(AUDIT_FILE, {"logins": []})
    logs = data.get("logins", [])
    logs.append(entry)
    data["logins"] = logs[-200:]
    save_json(AUDIT_FILE, data)


def list_audit_logins() -> List[Dict[str, Any]]:
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    """
                    SELECT al.username, al.timestamp, al.ip, al.user_agent,
                           u.email, u.phone, r.role_name AS role
                    FROM audit_logins al
                    LEFT JOIN users u ON u.username=al.username
                    LEFT JOIN roles r ON r.role_id=u.role_id
                    ORDER BY al.id DESC
                    LIMIT 200
                    """
                )
                rows = cur.fetchall() or []
                out: List[Dict[str, Any]] = []
                for r in rows:
                    out.append({
                        "username": r.get("username"),
                        "timestamp": str(r.get("timestamp")),
                        "ip": r.get("ip"),
                        "user_agent": r.get("user_agent"),
                        "email": r.get("email", ""),
                        "phone": r.get("phone", ""),
                        "role": r.get("role", ""),
                    })
                return out
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    logs = load_json(AUDIT_FILE, {"logins": []}).get("logins", [])
    # Ensure enrichment present
    out: List[Dict[str, Any]] = []
    for e in logs:
        if not (e.get("role") and e.get("email") is not None and e.get("phone") is not None):
            u = get_user(e.get("username", ""))
            if u:
                e = dict(e)
                e.setdefault("role", u.get("role", ""))
                e.setdefault("email", u.get("email", ""))
                e.setdefault("phone", u.get("phone", ""))
        out.append(e)
    return out


def archive_audit_logins() -> bool:
    """Move current login audit entries into archive and clear active log.

    Returns True if any entries were archived.
    """
    data = load_json(AUDIT_FILE, {"logins": []})
    logs = data.get("logins", [])
    if not logs:
        return False
    arch = load_json(AUDIT_ARCHIVE_FILE, {"logins": []})
    arch_logs = arch.get("logins", [])
    arch_logs.extend(logs)
    arch["logins"] = arch_logs[-1000:]
    save_json(AUDIT_ARCHIVE_FILE, arch)
    data["logins"] = []
    save_json(AUDIT_FILE, data)
    return True


def list_audit_login_archives() -> List[Dict[str, Any]]:
    return load_json(AUDIT_ARCHIVE_FILE, {"logins": []}).get("logins", [])


def restore_audit_logins() -> bool:
    """Restore archived login audit entries back into active log.

    Does not clear the archive; it copies entries so you have a combined history.
    Returns True if any entries were restored.
    """
    arch = load_json(AUDIT_ARCHIVE_FILE, {"logins": []})
    logs = arch.get("logins", [])
    if not logs:
        return False
    data = load_json(AUDIT_FILE, {"logins": []})
    act_logs = data.get("logins", [])
    act_logs.extend(logs)
    data["logins"] = act_logs[-1000:]
    save_json(AUDIT_FILE, data)
    return True


def _json_delete_user(username: str) -> bool:
    """Delete a user and related JSON traces (accounts and audit logs)."""
    changed = False
    # users
    db = _load_users()
    users = [u for u in db.get("users", []) if u.get("username") != username]
    if len(users) != len(db.get("users", [])):
        db["users"] = users
        _save_users(db)
        changed = True
    # accounts
    acc = load_json(ACCOUNTS_FILE, {"accounts": []})
    acc["accounts"] = [a for a in acc.get("accounts", []) if (a.get("username") if isinstance(a, dict) else a) != username]
    save_json(ACCOUNTS_FILE, acc)
    # audit logs
    audit = load_json(AUDIT_FILE, {"logins": []})
    audit["logins"] = [e for e in audit.get("logins", []) if e.get("username") != username]
    save_json(AUDIT_FILE, audit)
    return changed


def add_audit_event(event: Dict[str, Any]) -> None:
    """Generic audit trail for record changes.
    event keys: kind, action, username, details, timestamp
    """
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO audit_events (kind, action, username, timestamp, details)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (
                        event.get("kind"),
                        event.get("action"),
                        event.get("username"),
                        event.get("timestamp"),
                        json.dumps(event.get("details", {}), ensure_ascii=False),
                    ),
                )
                conn.commit()
                return
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    
    # Use thread lock to prevent race conditions when accessing the file
    with _audit_events_lock:
        data = load_json(AUDIT_EVENTS_FILE, {"events": []})
        evs = data.get("events", [])
        evs.append(event)
        data["events"] = evs[-1000:]
        save_json(AUDIT_EVENTS_FILE, data)


def list_audit_events(kind: str = "", limit: int = 100) -> List[Dict[str, Any]]:
    try:
        if _mysql_enabled():
            conn = _get_conn()
            try:
                cur = conn.cursor(dictionary=True)
                if kind:
                    cur.execute(
                        "SELECT kind, action, username, timestamp, details FROM audit_events WHERE kind=%s ORDER BY id DESC LIMIT %s",
                        (kind, limit),
                    )
                else:
                    cur.execute("SELECT kind, action, username, timestamp, details FROM audit_events ORDER BY id DESC LIMIT %s", (limit,))
                rows = cur.fetchall() or []
                out: List[Dict[str, Any]] = []
                for r in rows:
                    det = r.get("details")
                    try:
                        det_obj = json.loads(det) if isinstance(det, str) else det
                    except Exception:
                        det_obj = {}
                    out.append({
                        "kind": r.get("kind"),
                        "action": r.get("action"),
                        "username": r.get("username"),
                        "timestamp": str(r.get("timestamp")),
                        "details": det_obj,
                    })
                return out
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
    except Exception:
        pass
    
    with _audit_events_lock:
        evs = load_json(AUDIT_EVENTS_FILE, {"events": []}).get("events", [])
        if kind:
            evs = [e for e in evs if e.get("kind") == kind]
        return list(reversed(evs))[:limit]


def archive_audit_events() -> bool:
    """Move current audit_events entries into archive and clear active events.

    Returns True if any entries were archived.
    """
    with _audit_events_lock:
        data = load_json(AUDIT_EVENTS_FILE, {"events": []})
        evs = data.get("events", [])
        if not evs:
            return False
        arch = load_json(AUDIT_EVENTS_ARCHIVE_FILE, {"events": []})
        arch_evs = arch.get("events", [])
        arch_evs.extend(evs)
        arch["events"] = arch_evs[-1000:]
        save_json(AUDIT_EVENTS_ARCHIVE_FILE, arch)
        data["events"] = []
        save_json(AUDIT_EVENTS_FILE, data)
        return True


def list_audit_event_archives() -> List[Dict[str, Any]]:
    return load_json(AUDIT_EVENTS_ARCHIVE_FILE, {"events": []}).get("events", [])


def restore_audit_events() -> bool:
    """Restore archived audit_events entries back into active events.

    Does not clear the archive; it copies entries so you have a combined history.
    Returns True if any entries were restored.
    """
    with _audit_events_lock:
        arch = load_json(AUDIT_EVENTS_ARCHIVE_FILE, {"events": []})
        evs = arch.get("events", [])
        if not evs:
            return False
        data = load_json(AUDIT_EVENTS_FILE, {"events": []})
        act_evs = data.get("events", [])
        act_evs.extend(evs)
        data["events"] = act_evs[-1000:]
        save_json(AUDIT_EVENTS_FILE, data)
        return True











def get_current_audit_session_info() -> Dict[str, Any]:
    """Get information about the current audit session.
    
    Returns:
        Dictionary with session start time, event count, and session initiator
    """
    try:
        # Get all events
        all_events = list_audit_events("", limit=1000)
        
        # Find the most recent "new_session_started" event
        session_start_event = None
        for event in all_events:
            if event.get("kind") == "audit_management" and event.get("action") == "new_session_started":
                session_start_event = event
                break
        
        # Count events since session start
        if session_start_event:
            session_start_time = session_start_event.get("timestamp")
            session_initiator = session_start_event.get("username")
            
            # Count events after session start
            import datetime
            try:
                start_dt = datetime.datetime.fromisoformat(session_start_time)
                events_in_session = [
                    e for e in all_events 
                    if datetime.datetime.fromisoformat(e.get("timestamp", "")) >= start_dt
                ]
                event_count = len(events_in_session) - 1  # Exclude the session start event itself
            except Exception:
                event_count = len(all_events)
        else:
            # No explicit session start found, use first event timestamp
            if all_events:
                session_start_time = all_events[-1].get("timestamp")
                session_initiator = "system"
                event_count = len(all_events)
            else:
                session_start_time = datetime.datetime.now().isoformat()
                session_initiator = "system"
                event_count = 0
        
        return {
            "session_start": session_start_time,
            "session_initiator": session_initiator,
            "event_count": event_count,
            "has_explicit_session": session_start_event is not None
        }
    except Exception as e:
        logger.error(f"Error getting audit session info: {e}")
        import datetime
        return {
            "session_start": datetime.datetime.now().isoformat(),
            "session_initiator": "unknown",
            "event_count": 0,
            "has_explicit_session": False
        }
