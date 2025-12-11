-- Fix missing columns in patients table for CRUD operations
USE hospital_system;

-- Add blood_type_encrypted column if it doesn't exist
ALTER TABLE patients 
ADD COLUMN IF NOT EXISTS blood_type_encrypted TEXT AFTER allergies_encrypted;

-- Verify the changes
DESCRIBE patients;
