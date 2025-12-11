"""MySQL CRUD operations for clinical modules."""
import datetime
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def _log_audit_event(kind: str, action: str, username: str, details: Dict[str, Any]) -> None:
    """Helper to log audit events."""
    try:
        from utils.storage import add_audit_event
        add_audit_event({
            "kind": kind,
            "action": action,
            "username": username,
            "timestamp": datetime.datetime.now().isoformat(),
            "details": details
        })
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")


def _split_name(full: str) -> tuple:
    """Split a full name into first and last name."""
    full = (full or "").strip()
    if not full:
        return "", ""
    parts = full.split()
    if len(parts) == 1:
        return parts[0], ""
    return " ".join(parts[:-1]), parts[-1]


def add_mysql_record(kind: str, record: Dict[str, Any], conn, encrypt_text_func, username: str = "system") -> bool:
    """Add a new record to MySQL database for clinical modules.
    
    Args:
        kind: The table/module type (patients_db, appointments, diagnoses, prescriptions, medical_store, doctors)
        record: Dictionary containing the record data with column names as keys
        conn: MySQL connection object
        encrypt_text_func: Function to encrypt text
        username: Username performing the action (for audit logging)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        cur = conn.cursor()
        
        if kind == "doctors":
            # doctors table: first_name, last_name, specialization, contact_number
            first, last = _split_name(record.get("Name", ""))
            cur.execute(
                """
                INSERT INTO doctors (first_name, last_name, specialization, contact_number)
                VALUES (%s, %s, %s, %s)
                """,
                (first, last, record.get("Specialty", ""), record.get("Contact", ""))
            )
        
        elif kind == "patients_db":
            # patients table: first_name, last_name, last_name_encrypted, birthdate, gender, contact_number, allergies_encrypted
            first_name = record.get("First Name", "")
            last_name = record.get("Last Name", "")
            last_name_encrypted = encrypt_text_func(last_name) if last_name else ""
            
            # Calculate birthdate from age if provided
            age_str = record.get("Age", "")
            birthdate = None
            if age_str and age_str.isdigit():
                age = int(age_str)
                today = datetime.date.today()
                birthdate = datetime.date(today.year - age, today.month, today.day)
            
            contact = record.get("Contact", "")
            contact_encrypted = encrypt_text_func(contact) if contact else ""
            
            allergies = record.get("Allergies", "")
            allergies_encrypted = encrypt_text_func(allergies) if allergies else ""
            
            cur.execute(
                """
                INSERT INTO patients (first_name, last_name, last_name_encrypted, birthdate, gender, 
                                     contact_number, allergies_encrypted)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (first_name, last_name, last_name_encrypted, birthdate, record.get("Gender", ""),
                 contact_encrypted, allergies_encrypted)
            )
        
        elif kind == "appointments":
            # appointments table: patient_id, doctor_id, appointment_date, status
            # Need to resolve patient and doctor names to IDs
            patient_name = record.get("Patient Name", "")
            doctor_name = record.get("Doctor Name", "")
            
            # Find patient_id
            patient_first, patient_last = _split_name(patient_name)
            cur.execute(
                "SELECT patient_id FROM patients WHERE first_name=%s AND last_name=%s LIMIT 1",
                (patient_first, patient_last)
            )
            patient_row = cur.fetchone()
            patient_id = int(patient_row[0]) if patient_row else None
            
            # Find doctor_id
            doctor_first, doctor_last = _split_name(doctor_name)
            cur.execute(
                "SELECT doctor_id FROM doctors WHERE first_name=%s AND last_name=%s LIMIT 1",
                (doctor_first, doctor_last)
            )
            doctor_row = cur.fetchone()
            doctor_id = int(doctor_row[0]) if doctor_row else None
            
            if not patient_id or not doctor_id:
                logger.error(f"Could not find patient or doctor for appointment: {patient_name}, {doctor_name}")
                return False
            
            # Combine date and time
            date_str = record.get("Date", "")
            time_str = record.get("Time", "")
            appointment_datetime = None
            if date_str:
                try:
                    if time_str:
                        appointment_datetime = datetime.datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
                    else:
                        appointment_datetime = datetime.datetime.strptime(date_str, "%Y-%m-%d")
                except Exception:
                    appointment_datetime = datetime.datetime.now()
            
            cur.execute(
                """
                INSERT INTO appointments (patient_id, doctor_id, appointment_date, status)
                VALUES (%s, %s, %s, %s)
                """,
                (patient_id, doctor_id, appointment_datetime, record.get("Status", "Scheduled"))
            )
        
        elif kind == "diagnoses":
            # diagnoses table: patient_id, doctor_id, diagnosis_encrypted, notes_encrypted, created_at
            patient_name = record.get("Patient Name", "")
            doctor_name = record.get("Doctor Name", "")
            
            # Find patient_id
            patient_first, patient_last = _split_name(patient_name)
            cur.execute(
                "SELECT patient_id FROM patients WHERE first_name=%s AND last_name=%s LIMIT 1",
                (patient_first, patient_last)
            )
            patient_row = cur.fetchone()
            patient_id = int(patient_row[0]) if patient_row else None
            
            # Find doctor_id
            doctor_first, doctor_last = _split_name(doctor_name)
            cur.execute(
                "SELECT doctor_id FROM doctors WHERE first_name=%s AND last_name=%s LIMIT 1",
                (doctor_first, doctor_last)
            )
            doctor_row = cur.fetchone()
            doctor_id = int(doctor_row[0]) if doctor_row else None
            
            if not patient_id or not doctor_id:
                logger.error(f"Could not find patient or doctor for diagnosis: {patient_name}, {doctor_name}")
                return False
            
            diagnosis = record.get("Diagnosis", "")
            notes = record.get("Notes", "")
            notes_encrypted = encrypt_text_func(notes) if notes else ""
            
            cur.execute(
                """
                INSERT INTO diagnoses (patient_id, doctor_id, diagnosis_encrypted, notes_encrypted, created_at)
                VALUES (%s, %s, %s, %s, NOW())
                """,
                (patient_id, doctor_id, diagnosis, notes_encrypted)
            )
        
        elif kind == "prescriptions":
            # prescriptions table: patient_id, doctor_id, medications_encrypted, notes_encrypted, created_at
            patient_name = record.get("Patient Name", "")
            doctor_name = record.get("Doctor Name", "")
            
            # Find patient_id
            patient_first, patient_last = _split_name(patient_name)
            cur.execute(
                "SELECT patient_id FROM patients WHERE first_name=%s AND last_name=%s LIMIT 1",
                (patient_first, patient_last)
            )
            patient_row = cur.fetchone()
            patient_id = int(patient_row[0]) if patient_row else None
            
            # Find doctor_id
            doctor_first, doctor_last = _split_name(doctor_name)
            cur.execute(
                "SELECT doctor_id FROM doctors WHERE first_name=%s AND last_name=%s LIMIT 1",
                (doctor_first, doctor_last)
            )
            doctor_row = cur.fetchone()
            doctor_id = int(doctor_row[0]) if doctor_row else None
            
            if not patient_id or not doctor_id:
                logger.error(f"Could not find patient or doctor for prescription: {patient_name}, {doctor_name}")
                return False
            
            medications = record.get("Medications", "")
            notes = record.get("Notes", "")
            notes_encrypted = encrypt_text_func(notes) if notes else ""
            
            cur.execute(
                """
                INSERT INTO prescriptions (patient_id, doctor_id, medications_encrypted, notes_encrypted, created_at)
                VALUES (%s, %s, %s, %s, NOW())
                """,
                (patient_id, doctor_id, medications, notes_encrypted)
            )
        
        elif kind == "medical_store":
            # medical_inventory table: item_name, stock_quantity, sensitive_flag, created_at
            quantity_str = record.get("Quantity", "0")
            try:
                quantity = int(quantity_str)
            except Exception:
                quantity = 0
            
            notes = record.get("Notes", "")
            sensitive_flag = 1 if "sensitive" in notes.lower() else 0
            
            cur.execute(
                """
                INSERT INTO medical_inventory (item_name, stock_quantity, sensitive_flag, created_at)
                VALUES (%s, %s, %s, NOW())
                """,
                (record.get("Name", ""), quantity, sensitive_flag)
            )
        
        else:
            logger.error(f"Unknown kind for add_mysql_record: {kind}")
            return False
        
        conn.commit()
        cur.close()
        
        # Log audit event
        _log_audit_event(kind, "add", username, {"record": record})
        
        return True
        
    except Exception as e:
        logger.error(f"Error adding MySQL record for {kind}: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False


def update_mysql_record(kind: str, record_id: int, record: Dict[str, Any], conn, encrypt_text_func, username: str = "system") -> bool:
    """Update an existing record in MySQL database for clinical modules.
    
    Args:
        kind: The table/module type
        record_id: The primary key ID of the record to update
        record: Dictionary containing the updated record data
        conn: MySQL connection object
        encrypt_text_func: Function to encrypt text
        username: Username performing the action (for audit logging)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        cur = conn.cursor()
        
        if kind == "doctors":
            first, last = _split_name(record.get("Name", ""))
            cur.execute(
                """
                UPDATE doctors 
                SET first_name=%s, last_name=%s, specialization=%s, contact_number=%s
                WHERE doctor_id=%s
                """,
                (first, last, record.get("Specialty", ""), record.get("Contact", ""), record_id)
            )
        
        elif kind == "patients_db":
            first_name = record.get("First Name", "")
            last_name = record.get("Last Name", "")
            
            # Only encrypt if not already encrypted
            if last_name and not last_name.startswith("gAAAA"):
                last_name_encrypted = encrypt_text_func(last_name)
            else:
                last_name_encrypted = last_name
            
            # Calculate birthdate from age if provided
            age_str = record.get("Age", "")
            birthdate = None
            if age_str and age_str.isdigit():
                age = int(age_str)
                today = datetime.date.today()
                birthdate = datetime.date(today.year - age, today.month, today.day)
            
            contact = record.get("Contact", "")
            if contact and not contact.startswith("gAAAA"):
                contact_encrypted = encrypt_text_func(contact)
            else:
                contact_encrypted = contact
            
            allergies = record.get("Allergies", "")
            if allergies and not allergies.startswith("gAAAA"):
                allergies_encrypted = encrypt_text_func(allergies)
            else:
                allergies_encrypted = allergies
            
            cur.execute(
                """
                UPDATE patients 
                SET first_name=%s, last_name=%s, last_name_encrypted=%s, birthdate=%s, gender=%s,
                    contact_number=%s, allergies_encrypted=%s
                WHERE patient_id=%s
                """,
                (first_name, last_name, last_name_encrypted, birthdate, record.get("Gender", ""),
                 contact_encrypted, allergies_encrypted, record_id)
            )
        
        elif kind == "appointments":
            # Resolve patient and doctor names to IDs
            patient_name = record.get("Patient Name", "")
            doctor_name = record.get("Doctor Name", "")
            
            patient_first, patient_last = _split_name(patient_name)
            cur.execute(
                "SELECT patient_id FROM patients WHERE first_name=%s AND last_name=%s LIMIT 1",
                (patient_first, patient_last)
            )
            patient_row = cur.fetchone()
            patient_id = int(patient_row[0]) if patient_row else None
            
            doctor_first, doctor_last = _split_name(doctor_name)
            cur.execute(
                "SELECT doctor_id FROM doctors WHERE first_name=%s AND last_name=%s LIMIT 1",
                (doctor_first, doctor_last)
            )
            doctor_row = cur.fetchone()
            doctor_id = int(doctor_row[0]) if doctor_row else None
            
            if not patient_id or not doctor_id:
                logger.error(f"Could not find patient or doctor for appointment update: {patient_name}, {doctor_name}")
                return False
            
            date_str = record.get("Date", "")
            time_str = record.get("Time", "")
            appointment_datetime = None
            if date_str:
                try:
                    if time_str:
                        appointment_datetime = datetime.datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
                    else:
                        appointment_datetime = datetime.datetime.strptime(date_str, "%Y-%m-%d")
                except Exception:
                    pass
            
            cur.execute(
                """
                UPDATE appointments 
                SET patient_id=%s, doctor_id=%s, appointment_date=%s, status=%s
                WHERE appointment_id=%s
                """,
                (patient_id, doctor_id, appointment_datetime, record.get("Status", ""), record_id)
            )
        
        elif kind == "diagnoses":
            patient_name = record.get("Patient Name", "")
            doctor_name = record.get("Doctor Name", "")
            
            patient_first, patient_last = _split_name(patient_name)
            cur.execute(
                "SELECT patient_id FROM patients WHERE first_name=%s AND last_name=%s LIMIT 1",
                (patient_first, patient_last)
            )
            patient_row = cur.fetchone()
            patient_id = int(patient_row[0]) if patient_row else None
            
            doctor_first, doctor_last = _split_name(doctor_name)
            cur.execute(
                "SELECT doctor_id FROM doctors WHERE first_name=%s AND last_name=%s LIMIT 1",
                (doctor_first, doctor_last)
            )
            doctor_row = cur.fetchone()
            doctor_id = int(doctor_row[0]) if doctor_row else None
            
            if not patient_id or not doctor_id:
                logger.error(f"Could not find patient or doctor for diagnosis update: {patient_name}, {doctor_name}")
                return False
            
            diagnosis = record.get("Diagnosis", "")
            notes = record.get("Notes", "")
            if notes and not notes.startswith("gAAAA"):
                notes_encrypted = encrypt_text_func(notes)
            else:
                notes_encrypted = notes
            
            cur.execute(
                """
                UPDATE diagnoses 
                SET patient_id=%s, doctor_id=%s, diagnosis_encrypted=%s, notes_encrypted=%s
                WHERE diagnosis_id=%s
                """,
                (patient_id, doctor_id, diagnosis, notes_encrypted, record_id)
            )
        
        elif kind == "prescriptions":
            patient_name = record.get("Patient Name", "")
            doctor_name = record.get("Doctor Name", "")
            
            patient_first, patient_last = _split_name(patient_name)
            cur.execute(
                "SELECT patient_id FROM patients WHERE first_name=%s AND last_name=%s LIMIT 1",
                (patient_first, patient_last)
            )
            patient_row = cur.fetchone()
            patient_id = int(patient_row[0]) if patient_row else None
            
            doctor_first, doctor_last = _split_name(doctor_name)
            cur.execute(
                "SELECT doctor_id FROM doctors WHERE first_name=%s AND last_name=%s LIMIT 1",
                (doctor_first, doctor_last)
            )
            doctor_row = cur.fetchone()
            doctor_id = int(doctor_row[0]) if doctor_row else None
            
            if not patient_id or not doctor_id:
                logger.error(f"Could not find patient or doctor for prescription update: {patient_name}, {doctor_name}")
                return False
            
            medications = record.get("Medications", "")
            notes = record.get("Notes", "")
            if notes and not notes.startswith("gAAAA"):
                notes_encrypted = encrypt_text_func(notes)
            else:
                notes_encrypted = notes
            
            cur.execute(
                """
                UPDATE prescriptions 
                SET patient_id=%s, doctor_id=%s, medications_encrypted=%s, notes_encrypted=%s
                WHERE prescription_id=%s
                """,
                (patient_id, doctor_id, medications, notes_encrypted, record_id)
            )
        
        elif kind == "medical_store":
            quantity_str = record.get("Quantity", "0")
            try:
                quantity = int(quantity_str)
            except Exception:
                quantity = 0
            
            notes = record.get("Notes", "")
            sensitive_flag = 1 if "sensitive" in notes.lower() else 0
            
            cur.execute(
                """
                UPDATE medical_inventory 
                SET item_name=%s, stock_quantity=%s, sensitive_flag=%s
                WHERE item_id=%s
                """,
                (record.get("Name", ""), quantity, sensitive_flag, record_id)
            )
        
        else:
            logger.error(f"Unknown kind for update_mysql_record: {kind}")
            return False
        
        conn.commit()
        rowcount = cur.rowcount
        cur.close()
        
        # Log audit event
        if rowcount > 0:
            _log_audit_event(kind, "update", username, {"record_id": record_id, "record": record})
        
        return rowcount > 0
        
    except Exception as e:
        logger.error(f"Error updating MySQL record for {kind}: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False


def delete_mysql_record(kind: str, record_id: int, conn, username: str = "system") -> bool:
    """Delete a record from MySQL database for clinical modules.
    
    Args:
        kind: The table/module type
        record_id: The primary key ID of the record to delete
        conn: MySQL connection object
        username: Username performing the action (for audit logging)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        cur = conn.cursor()
        
        if kind == "doctors":
            cur.execute("DELETE FROM doctors WHERE doctor_id=%s", (record_id,))
        elif kind == "patients_db":
            cur.execute("DELETE FROM patients WHERE patient_id=%s", (record_id,))
        elif kind == "appointments":
            cur.execute("DELETE FROM appointments WHERE appointment_id=%s", (record_id,))
        elif kind == "diagnoses":
            cur.execute("DELETE FROM diagnoses WHERE diagnosis_id=%s", (record_id,))
        elif kind == "prescriptions":
            cur.execute("DELETE FROM prescriptions WHERE prescription_id=%s", (record_id,))
        elif kind == "medical_store":
            cur.execute("DELETE FROM medical_inventory WHERE item_id=%s", (record_id,))
        else:
            logger.error(f"Unknown kind for delete_mysql_record: {kind}")
            return False
        
        conn.commit()
        rowcount = cur.rowcount
        cur.close()
        
        # Log audit event
        if rowcount > 0:
            _log_audit_event(kind, "delete", username, {"record_id": record_id})
        
        return rowcount > 0
        
    except Exception as e:
        logger.error(f"Error deleting MySQL record for {kind}: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False
