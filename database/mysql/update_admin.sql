-- Update or insert admin user with new password
-- This script ensures the admin account exists with the correct credentials

USE hospital_system;

-- Update existing admin user if exists, otherwise insert
INSERT INTO users (user_id, username, hashed_password, role_id, email, phone, pin_code) 
VALUES (1, 'admin', SHA2('Hospital@123', 256), 1, 'admin@hospital.com', '+10000000000', '123456')
ON DUPLICATE KEY UPDATE 
    username = 'admin',
    hashed_password = SHA2('Hospital@123', 256),
    role_id = 1,
    email = 'admin@hospital.com',
    phone = '+10000000000',
    pin_code = '123456';

-- Verify the admin user was created
SELECT user_id, username, role_id, email, phone FROM users WHERE username = 'admin';

-- Show the admin role
SELECT r.role_name, u.username 
FROM users u 
JOIN roles r ON u.role_id = r.role_id 
WHERE u.username = 'admin';
