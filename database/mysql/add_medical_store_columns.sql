-- ===========================================
-- ADD MISSING COLUMNS TO MEDICAL_INVENTORY TABLE
-- ===========================================

USE hospital_system;

-- Add Unit Price column
ALTER TABLE medical_inventory 
ADD COLUMN unit_price DECIMAL(10,2) DEFAULT 0.00 AFTER stock_quantity;

-- Add Expiration Date column
ALTER TABLE medical_inventory 
ADD COLUMN expiration_date DATE DEFAULT NULL AFTER unit_price;

-- Add Notes column (replacing the simple sensitive_flag with more detailed notes)
ALTER TABLE medical_inventory 
ADD COLUMN notes TEXT DEFAULT NULL AFTER expiration_date;

-- Update existing records to migrate sensitive_flag to notes
UPDATE medical_inventory 
SET notes = CASE 
    WHEN sensitive_flag = 1 THEN 'Sensitive item - requires special handling'
    ELSE 'Standard inventory item'
END
WHERE notes IS NULL;

-- Optional: Remove the old sensitive_flag column (uncomment if you want to clean up)
-- ALTER TABLE medical_inventory DROP COLUMN sensitive_flag;

-- Show the updated table structure
DESCRIBE medical_inventory;