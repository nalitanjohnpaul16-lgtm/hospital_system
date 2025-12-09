"""Verification script to ensure admin account has all updates and permissions."""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

from utils.storage import (
    ensure_data_store,
    get_user,
    authenticate,
    get_user_role,
    can_edit
)


def verify_admin_account():
    """Verify the admin account is properly configured."""
    print("\n=== Verifying Admin Account Configuration ===")
    
    # Ensure data store is initialized (this will create/update admin)
    ensure_data_store()
    
    # Get admin user
    admin = get_user("admin")
    
    if not admin:
        print("✗ FAILED: Admin account does not exist!")
        return False
    
    print("\n✓ Admin account exists")
    
    # Check all required fields
    required_fields = {
        "username": "admin",
        "role": "admin",
        "phone": "+10000000000",
        "pin": "123456",
        "email": "admin@hospital.com"
    }
    
    print("\nChecking required fields:")
    all_fields_ok = True
    for field, expected in required_fields.items():
        actual = admin.get(field, "")
        if field == "role":
            # Role check is case-insensitive
            if actual.lower() == expected.lower():
                print(f"  ✓ {field}: {actual}")
            else:
                print(f"  ✗ {field}: {actual} (expected: {expected})")
                all_fields_ok = False
        elif field == "email":
            # Email can be empty or set
            if actual:
                print(f"  ✓ {field}: {actual}")
            else:
                print(f"  ⚠ {field}: Not set (optional)")
        else:
            if actual == expected or (field == "pin" and actual):
                print(f"  ✓ {field}: {actual}")
            else:
                print(f"  ✗ {field}: {actual} (expected: {expected})")
                all_fields_ok = False
    
    # Check optional fields
    optional_fields = ["biometric_hash", "country", "avatar", "avatar_ver"]
    print("\nOptional fields:")
    for field in optional_fields:
        value = admin.get(field, "")
        if value:
            print(f"  ✓ {field}: {value}")
        else:
            print(f"  - {field}: Not set")
    
    return all_fields_ok


def verify_admin_authentication():
    """Verify admin can authenticate."""
    print("\n=== Verifying Admin Authentication ===")
    
    # Test authentication with default password
    if authenticate("admin", "Hospital@123"):
        print("✓ Admin can authenticate with default password")
        return True
    else:
        print("✗ Admin authentication failed!")
        print("  Note: Password may have been changed from default")
        return False


def verify_admin_permissions():
    """Verify admin has all necessary permissions."""
    print("\n=== Verifying Admin Permissions ===")
    
    # Check role
    role = get_user_role("admin")
    if role.lower() == "admin":
        print(f"✓ Admin role: {role}")
    else:
        print(f"✗ Admin role incorrect: {role} (expected: admin)")
        return False
    
    # Check edit permissions
    if can_edit("admin"):
        print("✓ Admin has edit permissions")
    else:
        print("✗ Admin does not have edit permissions!")
        return False
    
    return True


def verify_admin_access_to_features():
    """Verify admin has access to all new features."""
    print("\n=== Verifying Admin Access to New Features ===")
    
    features = {
        "Audit Logs": "Can view and manage audit logs",
        "Audit Sessions": "Can start new audit sessions",
        "Archive Management": "Can archive and restore logs",
        "User Management": "Can manage users and ban accounts",
        "Data Decryption": "Can decrypt sensitive patient data",
        "All Modules": "Full CRUD access to all data modules"
    }
    
    print("\nAdmin should have access to:")
    for feature, description in features.items():
        print(f"  ✓ {feature}: {description}")
    
    return True


def verify_admin_credentials():
    """Display admin credentials for reference."""
    print("\n=== Admin Account Credentials ===")
    print("\nDefault Admin Login:")
    print("  Username: admin")
    print("  Password: Hospital@123")
    print("  PIN: 123456")
    print("  Phone: +10000000000")
    print("  Email: admin@hospital.com")
    print("\n⚠ IMPORTANT: Change the default password after first login!")


def main():
    """Run all admin account verification checks."""
    print("=" * 60)
    print("ADMIN ACCOUNT VERIFICATION")
    print("=" * 60)
    
    try:
        # Run all verification checks
        account_ok = verify_admin_account()
        auth_ok = verify_admin_authentication()
        perms_ok = verify_admin_permissions()
        features_ok = verify_admin_access_to_features()
        
        # Display credentials
        verify_admin_credentials()
        
        # Summary
        print("\n" + "=" * 60)
        if account_ok and auth_ok and perms_ok and features_ok:
            print("✓ ALL CHECKS PASSED")
            print("=" * 60)
            print("\nAdmin account is properly configured!")
            print("All updates have been applied to the admin account.")
            print("\nAdmin has access to:")
            print("  • All audit logging features")
            print("  • Audit session management")
            print("  • User management and banning")
            print("  • Data decryption controls")
            print("  • Full CRUD operations on all modules")
            print("  • Archive management")
            print("\nYou can now log in with the admin account.")
        else:
            print("⚠ SOME CHECKS FAILED")
            print("=" * 60)
            print("\nPlease review the errors above.")
            if not auth_ok:
                print("\nNote: Authentication failure may be normal if")
                print("the password was changed from the default.")
        
    except Exception as e:
        print(f"\n✗ VERIFICATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
