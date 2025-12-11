-- Update database schema to support encryption for all clinical modules

-- Update doctors table to support encrypted contact information
ALTER TABLE doctors 
MODIFY COLUMN contact_number TEXT;

-- Add encrypted contact field for doctors
ALTER TABLE doctors 
ADD COLUMN contact_number_encrypted TEXT AFTER contact_number;

-- Update appointments table to support encrypted status
ALTER TABLE appointments 
ADD COLUMN status_encrypted TEXT AFTER status;

-- Update appointments table to use TEXT for status to support encryption
-- First, let's see what we have
SELECT 'Current appointments status values:' as info;
SELECT DISTINCT status FROM appointments;

-- We'll keep the ENUM for compatibility but add encrypted field
-- The application will use status_encrypted when encryption is enabled