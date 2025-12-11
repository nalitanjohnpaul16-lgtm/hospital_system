-- Remove blood_type_encrypted column from patients table
-- Run this script to update your existing database

USE hospital_system;

-- Check if column exists before dropping
ALTER TABLE patients DROP COLUMN IF EXISTS blood_type_encrypted;
