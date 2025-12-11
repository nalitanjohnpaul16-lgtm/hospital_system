-- ===========================================
-- HOSPITAL SYSTEM - ENTERPRISE SECURE SCHEMA
-- ===========================================


CREATE DATABASE hospital_system;
USE hospital_system;

-- ===========================================
-- 0. ROLES (RBAC)
-- ===========================================
CREATE TABLE roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE
);

-- ===========================================
-- 1. USERS (LOGIN ACCOUNTS)
-- ===========================================
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    email VARCHAR(150) DEFAULT NULL,
    phone VARCHAR(20) DEFAULT NULL,
    pin_code VARCHAR(10) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

-- ===========================================
-- 2. DOCTORS
-- ===========================================
CREATE TABLE doctors (
    doctor_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    specialization VARCHAR(150) NOT NULL,
    contact_number VARCHAR(20),
    email VARCHAR(150),
    pin_code VARCHAR(10),
    biometric_face_data BLOB,
    biometric_fingerprint_data BLOB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- ===========================================
-- 3. PATIENTS
-- ===========================================
CREATE TABLE patients (
    patient_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    last_name_encrypted TEXT,
    birthdate DATE NOT NULL,
    gender ENUM('Male','Female','Other') NOT NULL,
    contact_number VARCHAR(20),
    address VARCHAR(255),
    allergies_encrypted TEXT,
    medical_history_encrypted TEXT,
    biometric_face_data BLOB,
    biometric_fingerprint_data BLOB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================================
-- 4. APPOINTMENTS
-- ===========================================
CREATE TABLE appointments (
    appointment_id INT AUTO_INCREMENT PRIMARY KEY,
    doctor_id INT NOT NULL,
    patient_id INT NOT NULL,
    enc_doctor_id TEXT DEFAULT NULL,
    enc_patient_id TEXT DEFAULT NULL,
    appointment_date DATETIME NOT NULL,
    purpose VARCHAR(255),
    status ENUM('Scheduled', 'Completed', 'Canceled') DEFAULT 'Scheduled',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id),
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
);

-- ===========================================
-- 5. DIAGNOSES
-- ===========================================
CREATE TABLE diagnoses (
    diagnosis_id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    diagnosis_encrypted TEXT NOT NULL,
    notes_encrypted TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
);

-- ===========================================
-- 6. PRESCRIPTIONS
-- ===========================================
CREATE TABLE prescriptions (
    prescription_id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    medications_encrypted TEXT NOT NULL,
    notes_encrypted TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
);

-- ===========================================
-- 7. MEDICAL INVENTORY
-- ===========================================
CREATE TABLE medical_inventory (
    item_id INT AUTO_INCREMENT PRIMARY KEY,
    item_name VARCHAR(150) NOT NULL,
    stock_quantity INT DEFAULT 0,
    sensitive_flag BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================================
-- 8. INVENTORY TRANSACTIONS
-- ===========================================
CREATE TABLE inventory_transactions (
    transaction_id INT AUTO_INCREMENT PRIMARY KEY,
    item_id INT NOT NULL,
    quantity INT NOT NULL,
    transaction_type ENUM('dispense', 'restock') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (item_id) REFERENCES medical_inventory(item_id)
);

-- ===========================================
-- 9. AUDIT LOGS
-- ===========================================
CREATE TABLE audit_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    event_description TEXT NOT NULL,
    event_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================================
-- 10. ASSETS (for risk register)
-- ===========================================
CREATE TABLE assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_name VARCHAR(120) NOT NULL,
    type VARCHAR(64) NOT NULL,
    value VARCHAR(64) NOT NULL,
    owner VARCHAR(120) NOT NULL,
    security_classification VARCHAR(64) NOT NULL
);

-- ===========================================
-- 11. THREATS & VULNERABILITIES
-- ===========================================
CREATE TABLE threats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    threat VARCHAR(255) NOT NULL,
    vulnerability VARCHAR(255) NOT NULL,
    likelihood VARCHAR(32) NOT NULL,
    impact VARCHAR(32) NOT NULL,
    countermeasure VARCHAR(255) NOT NULL
);

-- ===========================================
-- 12. INCIDENTS
-- ===========================================
CREATE TABLE incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    incident_type VARCHAR(255) NOT NULL,
    date_time VARCHAR(64) NOT NULL,
    affected_systems VARCHAR(255) NOT NULL,
    actions_taken VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL
);

-- ===========================================
-- 13. BUSINESS IMPACT ANALYSIS (BIA)
-- ===========================================
CREATE TABLE bia (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset VARCHAR(255) NOT NULL,
    threat_scenario VARCHAR(255) NOT NULL,
    financial_impact TEXT NOT NULL,
    operational_impact VARCHAR(64) NOT NULL,
    recovery_strategy VARCHAR(255) NOT NULL
);

-- ===========================================
-- 14. AUDIT LOGIN EVENTS (for dashboard recent logins)
-- ===========================================
CREATE TABLE audit_logins (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    timestamp DATETIME NOT NULL,
    ip VARCHAR(64) DEFAULT NULL,
    user_agent TEXT,
    INDEX (username),
    INDEX (timestamp)
);

-- ===========================================
-- 15. CRYPTOGRAPHY LOGS (demo outputs / events)
-- ===========================================
CREATE TABLE crypto_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    context VARCHAR(64) NOT NULL,
    output TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================================
-- 16. BIOMETRICS (user-centric storage)
-- ===========================================
CREATE TABLE biometrics (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    face_hash VARCHAR(128) DEFAULT NULL,
    fingerprint_hash VARCHAR(128) DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);


-- ===========================================
-- 17. INITIAL RBAC DATA (ADMIN ROLE & USER)
-- ===========================================
INSERT IGNORE INTO roles (role_name)
VALUES ('ADMIN');

INSERT IGNORE INTO roles (role_name)
VALUES
    ('DOCTOR'),
    ('NURSE'),
    ('RECEPTIONIST'),
    ('INVENTORY_STAFF'),
    ('IT_SECURITY'),
    ('PHARMACIST');

INSERT IGNORE INTO users (username, hashed_password, role_id, email, phone, pin_code)
VALUES (
    'admin',
    'hospital123',
    (SELECT role_id FROM roles WHERE role_name = 'ADMIN'),
    'admin@example.com',
    '0000000000',
    '1234'
);

-- Optional: seed biometrics for admin so checks can pass
INSERT IGNORE INTO biometrics (user_id, face_hash, fingerprint_hash)
VALUES (
    (SELECT user_id FROM users WHERE username = 'admin'),
    'ADMIN_FACE_HASH_PLACEHOLDER',
    'ADMIN_FINGERPRINT_HASH_PLACEHOLDER'
);

