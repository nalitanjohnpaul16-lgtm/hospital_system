from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, send_from_directory, jsonify
import os
import io
import sys
import time
import logging
from functools import wraps
import mysql.connector  # type: ignore
from mysql.connector import pooling, Error  # type: ignore
try:
    from PIL import Image  # type: ignore
except Exception:
    Image = None  # type: ignore

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from utils.storage import ensure_data_store, authenticate, list_records, save_records, can_edit, get_user_role, create_user, generate_mfa_code, verify_mfa_code, set_password, verify_pin, set_biometric_hash, verify_biometric_hash, encrypt_text, decrypt_text, encrypt_sensitive_data, decrypt_sensitive_data, is_encrypted_data, send_mfa_code, send_sms_code, update_user, is_valid_username, is_valid_phone, is_valid_email, is_valid_password, remember_account, list_accounts, remove_account, get_user, remove_saved_password, list_audit_events, list_audit_logins, archive_audit_logins, archive_audit_events, list_audit_login_archives, list_audit_event_archives, list_users, restore_audit_logins, restore_audit_events, add_mysql_record, update_mysql_record, delete_mysql_record, delete_user, ban_user, get_current_audit_session_info
from company_profile.company_info import show_company_profile
from risk_analysis.security_controls import show_security_controls
from compliance.legal_ethics import show_compliance
from business_impact.bia_analysis import bia as default_bia
from company_profile.asset_inventory import assets as default_assets
from risk_analysis.threat_vulnerability import matrix as default_threats
from cryptography_demo.encryption_demo import demo_encryption

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

ensure_data_store()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    base = os.path.join(os.path.dirname(__file__), 'assets')
    return send_from_directory(base, filename)

@app.route("/")
def index():
    if session.get("user"):
        # Auto-encrypt when navigating to home
        clear_phi_session_data()
        return redirect(url_for("overview"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"]) 
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember_pw = request.form.get("remember_pw") == "on"
        if authenticate(username, password):
            # Bypass MFA on normal login as requested; require PIN for edits
            session.pop("pending_user", None)
            session.pop("pin_ok", None)
            session.pop("pin_ok_until", None)
            session["user"] = username
            if remember_pw:
                remember_account(username, saved_password=password)
            else:
                remember_account(username)
            
            # Log successful login
            from utils.storage import add_audit_login
            import datetime
            add_audit_login({
                "username": username,
                "timestamp": datetime.datetime.now().isoformat(),
                "ip": request.remote_addr or "unknown",
                "user_agent": request.headers.get("User-Agent", "unknown")
            })
            
            return redirect(url_for("overview"))
        else:
            # Log failed login attempt
            from utils.storage import add_audit_event
            import datetime
            add_audit_event({
                "kind": "authentication",
                "action": "login_failed",
                "username": username,
                "timestamp": datetime.datetime.now().isoformat(),
                "details": {"ip": request.remote_addr or "unknown"}
            })
        flash("Invalid credentials", "error")
    return render_template("login.html", preset=request.args.get("username", ""))

@app.route("/mfa", methods=["GET", "POST"]) 
def mfa():
    pending = session.get("pending_user")
    if not pending:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if verify_mfa_code(pending, code):
            session.pop("pending_user", None)
            session["user"] = pending
            remember_account(pending)
            return redirect(url_for("overview"))
        flash("Invalid MFA code", "error")
    return render_template("mfa.html")

# Duplicate route removed - using serve_assets instead
# MySQL connection config via environment; connect lazily to avoid crash on bad creds
# Set: MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, MYSQL_POOL_SIZE
DB_CFG = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "jjppbbnn"),
    "database": os.getenv("MYSQL_DB", "hospital_system"),
    "autocommit": True
}

# Global connection pool
_DB_POOL = None

def get_db():
    """Get a database connection from the pool or create a new one."""
    global _DB_POOL
    
    # Try to get connection from pool
    if _DB_POOL is not None:
        try:
            conn = _DB_POOL.get_connection()
            logger.info("Got connection from pool")
            return conn
        except Error as e:
            logger.error(f"Error getting connection from pool: {e}")
    
    # Fall back to direct connection if pool fails or doesn't exist
    try:
        conn = mysql.connector.connect(**DB_CFG)
        logger.info("Created new direct database connection")
        return conn
    except Error as e:
        logger.error(f"Error connecting to database: {e}")
        return None

def _init_pool():
    """Initialize the database connection pool."""
    global _DB_POOL
    try:
        _DB_POOL = pooling.MySQLConnectionPool(
            pool_name="hms_pool",
            pool_size=int(os.getenv("MYSQL_POOL_SIZE", "5")),
            **DB_CFG,
        )
        logger.info("Database connection pool initialized successfully")
    except Error as e:
        _DB_POOL = None
        logger.error(f"Failed to initialize database connection pool: {e}")

# Initialize the connection pool when the module loads
_init_pool()

@app.route("/test-db")
def test_db():
    """Test endpoint to verify database connectivity."""
    try:
        conn = get_db()
        if conn is None:
            return jsonify({"status": "error", "message": "Failed to connect to database"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT 1 as test_value")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result and result['test_value'] == 1:
            return jsonify({
                "status": "success", 
                "message": "Database connection successful!",
                "database": DB_CFG["database"],
                "host": DB_CFG["host"]
            })
        return jsonify({"status": "error", "message": "Unexpected database response"}), 500
    except Error as e:
        return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

@app.route("/signup", methods=["GET", "POST"]) 
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        country = request.form.get("country", "").strip()
        role_raw = (request.form.get("role") or "").strip().lower()
        specialty = (request.form.get("specialty") or "").strip()
        role_map = {
            "asset_manager": "asset_manager",
            "auditor": "auditor",
            "doctor": "doctor",
            "inventory_staff": "inventory",
            "it_security": "it_security",
            "nurse": "nurse",
            # Patients and Other roles have specific permissions
            "patients": "patients",
            "other": "other",
            "": "visitor",
        }
        role = role_map.get(role_raw, "visitor")
        if not username or not password:
            flash("Username and password are required", "error")
        elif not is_valid_password(password):
            flash("Password must be at least 8 characters with 1 number, 1 capital letter, and 1 symbol", "error")
        else:
            ok = create_user(
                username,
                password,
                phone,
                "",
                role=role,
                email=email,
                country=country,
                specialty=specialty,
            )
            if ok:
                # Log user creation
                from utils.storage import add_audit_event
                import datetime
                add_audit_event({
                    "kind": "user_management",
                    "action": "user_created",
                    "username": username,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "details": {"role": role, "email": email}
                })
                
                # Auto-login new user and require biometric then PIN setup
                session["user"] = username
                flash("Account created. Please set your PIN, then enroll your biometric.")
                # First, force the user to set a 6-digit PIN, then go to biometric enrollment
                next_after_pin = url_for("biometric", next=url_for("overview"))
                return redirect(url_for("verify_pin_route", next=next_after_pin))
            else:
                flash("Username already exists", "error")
    return render_template("signup.html")

@app.route("/validate_username", methods=["GET", "POST"]) 
def validate_username():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            flash("Enter username", "error")
        else:
            user = get_user(username)
            if not user:
                flash("Username not found", "error")
            else:
                session["validated_username"] = username
                flash("Username validated. Choose how to receive your reset code.", "success")
                return redirect(url_for("forgot"))
    return render_template("validate_username.html")

@app.route("/forgot", methods=["GET"]) 
def forgot():
    if "validated_username" not in session:
        return redirect(url_for("validate_username"))
    return render_template("forgot.html")

@app.route("/verify_phone", methods=["POST"]) 
def verify_phone():
    username = session.get("validated_username")
    if not username:
        return redirect(url_for("validate_username"))
    phone_input = request.form.get("phone", "").strip()
    user = get_user(username)
    stored_phone = (user or {}).get("phone", "").strip()
    if not stored_phone:
        flash("No phone number on file for this account.", "error")
        return redirect(url_for("forgot"))
    if phone_input != stored_phone:
        flash("Phone number does not match our records.", "error")
        return redirect(url_for("forgot"))
    code = generate_mfa_code(username)
    sent_sms = send_sms_code(username, code)
    if not sent_sms:
        # Demo fallback: show the code directly if SMS gateway is not configured
        flash(f"SMS CODE: {code}", "info")
    else:
        flash("Reset code sent to your phone.", "success")
    session["reset_user"] = username
    return redirect(url_for("reset_code"))

@app.route("/verify_email", methods=["GET", "POST"]) 
def verify_email():
    username = session.get("validated_username")
    if not username:
        return redirect(url_for("validate_username"))
    user = get_user(username)
    preset = (user or {}).get("email", "").strip()
    if request.method == "POST":
        input_email = (request.form.get("email") or "").strip()
        stored_email = (user or {}).get("email", "").strip()
        if not stored_email:
            flash("No email address on file for this account.", "error")
            return redirect(url_for("forgot"))
        if input_email.lower() != stored_email.lower():
            flash("Email does not match our records.", "error")
            return render_template("verify_email.html", preset_email=preset)
        code = generate_mfa_code(username)
        sent_email = send_mfa_code(username, code)
        if not sent_email:
            # Demo fallback: show the code directly if email is not configured
            flash(f"EMAIL CODE: {code}", "info")
        else:
            flash("Reset code sent to your email.", "success")
        session["reset_user"] = username
        return redirect(url_for("reset_code"))
    return render_template("verify_email.html", preset_email=preset)

@app.route("/reset/code", methods=["GET", "POST"]) 
def reset_code():
    """Page where user enters the 6-digit reset code sent via email/SMS."""
    ru = session.get("reset_user")
    if not ru:
        return redirect(url_for("forgot"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not code:
            flash("Enter the 6-digit code", "error")
        elif not verify_mfa_code(ru, code):
            flash("Invalid or expired code", "error")
        else:
            session["code_ok"] = True
            flash("Code verified. You can now set a new password.", "success")
            return redirect(url_for("reset_password"))
    return render_template("reset_code.html")

@app.route("/reset", methods=["GET", "POST"]) 
def reset_password():
    ru = session.get("reset_user")
    if not ru:
        return redirect(url_for("forgot"))
    if request.method == "POST":
        newp = request.form.get("new_password", "")
        code_ok = bool(session.get("code_ok"))
        bio_ok = bool(session.get("bio_ok"))
        if not (code_ok or bio_ok):
            flash("You must verify a reset code first.", "error")
            return redirect(url_for("reset_code"))
        if not newp:
            flash("Enter new password", "error")
        elif not is_valid_password(newp):
            flash("Password must be at least 8 characters with 1 number, 1 capital letter, and 1 symbol", "error")
        else:
            set_password(ru, newp)
            
            # Log password change
            from utils.storage import add_audit_event
            import datetime
            add_audit_event({
                "kind": "user_management",
                "action": "password_changed",
                "username": ru,
                "timestamp": datetime.datetime.now().isoformat(),
                "details": {"method": "reset"}
            })
            
            session.pop("reset_user", None)
            session.pop("bio_ok", None)
            session.pop("code_ok", None)
            flash("Password updated. Please log in.")
            return redirect(url_for("login"))
    return render_template("reset_password.html")

@app.route("/verify_pin", methods=["GET", "POST"]) 
@login_required
def verify_pin_route():
    # Determine context for PIN verification
    next_url = request.args.get("next", "")
    context_message = ""
    
    # Check if this is for medical store access by a nurse
    username = session.get("user")
    user_role = (get_user(username) or {}).get("role", "").lower()
    
    if "medical_store" in next_url and user_role == "nurse":
        context_message = "PIN verification required for Medical Store access"
    elif any(module in next_url for module in ["patients_db", "appointments", "diagnoses", "prescriptions", "doctors"]):
        context_message = "PIN verification required for clinical data access"
    else:
        context_message = "PIN verification required to continue"
    
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        user = get_user(username)
        current_pin = (user or {}).get("pin", "")
        if not current_pin:
            # set a new PIN; must be 6 digits
            if pin and pin.isdigit() and len(pin) == 6:
                if update_user(username, {"pin": pin}):
                    flash("PIN set successfully")
                    session["pin_ok"] = True
                    session["pin_ok_until"] = int(time.time()) + 300
                    
                    # Log PIN verification for medical store access by nurses
                    if "medical_store" in next_url and user_role == "nurse":
                        from utils.storage import add_audit_event
                        import datetime
                        add_audit_event({
                            "kind": "authentication",
                            "action": "pin_verified_medical_store",
                            "username": username,
                            "timestamp": datetime.datetime.now().isoformat(),
                            "details": {"nurse_medical_store_access": True, "pin_set": True}
                        })
                    
                    next_url = request.args.get("next") or url_for("overview")
                    return redirect(next_url)
            flash("Enter a 6-digit PIN", "error")
        else:
            if verify_pin(username, pin):
                session["pin_ok"] = True
                session["pin_ok_until"] = int(time.time()) + 300
                
                # Log PIN verification for medical store access by nurses
                if "medical_store" in next_url and user_role == "nurse":
                    from utils.storage import add_audit_event
                    import datetime
                    add_audit_event({
                        "kind": "authentication",
                        "action": "pin_verified_medical_store",
                        "username": username,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "details": {"nurse_medical_store_access": True}
                    })
                
                next_url = request.args.get("next") or url_for("overview")
                return redirect(next_url)
            flash("Invalid PIN", "error")
    return render_template("pin.html", context_message=context_message)

@app.route("/biometric", methods=["GET", "POST"]) 
@login_required
def biometric():
    verify_only = (request.args.get("mode") == "verify")
    if request.method == "POST":
        action = request.form.get("action")
        file = request.files.get("image")
        if not file or not file.filename:
            flash("Upload an image", "error")
            return render_template("biometric.html", verify_only=verify_only)
        content = file.read()
        import hashlib
        bio_hash = hashlib.sha256(content).hexdigest()
        if action == "enroll":
            set_biometric_hash(session.get("user"), bio_hash)
            flash("Biometric enrolled")
            next_url = request.args.get("next")
            if next_url:
                return redirect(next_url)
            return redirect(url_for("biometric"))
        if action == "verify":
            if verify_biometric_hash(session.get("user"), bio_hash):
                session["bio_ok"] = True
                flash("Biometric verified")
                next_url = request.args.get("next") or url_for("overview")
                return redirect(next_url)
            flash("Biometric mismatch", "error")
    return render_template("biometric.html", verify_only=verify_only)

@app.route("/verify_biometric_reset", methods=["GET", "POST"]) 
def verify_biometric_reset():
    """Biometric verification for password reset (no login required)."""
    username = session.get("validated_username")
    if not username:
        flash("Please validate your username first.", "error")
        return redirect(url_for("validate_username"))
    
    if request.method == "POST":
        file = request.files.get("image")
        if not file or not file.filename:
            flash("Upload an image for biometric verification", "error")
            return render_template("biometric_reset.html")
        
        content = file.read()
        import hashlib
        bio_hash = hashlib.sha256(content).hexdigest()
        
        if verify_biometric_hash(username, bio_hash):
            session["bio_ok"] = True
            session["reset_user"] = username
            flash("Biometric verified successfully. You can now reset your password.", "success")
            return redirect(url_for("reset_password"))
        else:
            flash("Biometric verification failed. Please try again.", "error")
    
    return render_template("biometric_reset.html")

@app.route("/biometric/capture")
@login_required
def biometric_capture():
    return render_template("biometric_capture.html")

@app.route("/settings", methods=["GET", "POST"]) 
def settings():
    if request.method == "POST":
        theme = request.form.get("theme", "light")
        palette = request.form.get("palette", "default")
        session["theme"] = theme if theme in {"light", "dark"} else "light"
        # Accept UI palette options opt1-opt5 so chosen color palette persists correctly
        session["palette"] = palette if palette in {"opt1", "opt2", "opt3", "opt4", "opt5"} else "opt1"
        flash("Settings saved")
        return redirect(url_for("settings"))
    return render_template("settings.html")

@app.route("/account/delete", methods=["GET", "POST"]) 
@login_required
def delete_account_route():
    """Allow the logged-in user to permanently delete their own account.

    Requires username + password confirmation and a checkbox in delete_account.html.
    """
    current = session.get("user")
    if not current:
        return redirect(url_for("login"))
    if request.method == "POST":
        form_username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") == "on"

        if form_username != current:
            flash("Username does not match the logged-in account.", "error")
            return redirect(url_for("delete_account_route"))
        if not confirm:
            flash("You must confirm that deletion cannot be undone.", "error")
            return redirect(url_for("delete_account_route"))
        if not authenticate(current, password):
            flash("Incorrect password.", "error")
            return redirect(url_for("delete_account_route"))

        ok = delete_user(current)
        if ok:
            # Log account deletion
            from utils.storage import add_audit_event
            import datetime
            add_audit_event({
                "kind": "user_management",
                "action": "account_deleted",
                "username": current,
                "timestamp": datetime.datetime.now().isoformat(),
                "details": {"self_deletion": True}
            })
            
            session.clear()
            flash("Your account has been deleted.", "success")
            return redirect(url_for("login"))
        flash("Failed to delete account. Please contact an administrator.", "error")
        return redirect(url_for("settings"))

    return render_template("delete_account.html")

@app.route("/help") 
def help_center():
    return render_template("help.html")

@app.route("/profile", methods=["GET", "POST"]) 
@login_required
def profile():
    username = session.get("user")
    user = get_user(username)
    if request.method == "POST":
        # Require recent PIN approval to change profile data
        now = int(time.time())
        if not session.get("pin_ok") or now > int(session.get("pin_ok_until") or 0):
            return redirect(url_for("verify_pin_route", next=url_for("profile")))

        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        file = request.files.get("avatar")
        
        # Validate inputs
        if phone and not is_valid_phone(phone):
            flash("Invalid phone number", "error")
        elif email and not is_valid_email(email):
            flash("Invalid email", "error")
        elif new_password and not current_password:
            flash("Current password is required to change password", "error")
        elif new_password and not authenticate(username, current_password):
            flash("Current password is incorrect", "error")
        elif new_password and not is_valid_password(new_password):
            flash("New password must be at least 8 characters with 1 number, 1 capital letter, and 1 symbol", "error")
        else:
            avatar_path = None
            if file and file.filename:
                ext = os.path.splitext(file.filename)[1].lower()
                if ext in [".png", ".jpg", ".jpeg", ".gif"]:
                    avatar_dir = os.path.join(os.path.dirname(__file__), "static", "avatars")
                    os.makedirs(avatar_dir, exist_ok=True)
                    fname = f"{username}.png"
                    fpath = os.path.join(avatar_dir, fname)
                    try:
                        if Image is not None:
                            img = Image.open(file.stream).convert("RGB")
                            w, h = img.size
                            side = min(w, h)
                            left = (w - side) // 2
                            top = (h - side) // 2
                            img = img.crop((left, top, left + side, top + side))
                            img = img.resize((256, 256))
                            img.save(fpath, format="PNG")
                        else:
                            file.save(fpath)
                        avatar_path = f"/static/avatars/{fname}"
                    except Exception as e:
                        flash("Failed to process avatar image", "error")
            updates = {"phone": phone, "email": email}
            if avatar_path:
                # bump avatar version for cache busting
                try:
                    cur_ver = int((user or {}).get("avatar_ver", 0))
                except Exception:
                    cur_ver = 0
                updates.update({"avatar": avatar_path, "avatar_ver": cur_ver + 1})
            
            # Handle password change
            password_changed = False
            if new_password:
                if set_password(username, new_password):
                    password_changed = True
                    # Log password change
                    from utils.storage import add_audit_event
                    import datetime
                    add_audit_event({
                        "kind": "user_management",
                        "action": "password_changed",
                        "username": username,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "details": {"method": "profile_update"}
                    })
                else:
                    flash("Failed to update password", "error")
                    return redirect(url_for("profile"))
            
            # Update other profile fields
            if updates.get("phone") or updates.get("email") or avatar_path:
                if update_user(username, updates):
                    # Log profile update
                    from utils.storage import add_audit_event
                    import datetime
                    add_audit_event({
                        "kind": "user_management",
                        "action": "profile_updated",
                        "username": username,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "details": {"fields_updated": list(updates.keys())}
                    })
                else:
                    flash("Phone or email already in use", "error")
                    return redirect(url_for("profile"))
            
            # Success message
            if password_changed and (updates.get("phone") or updates.get("email") or avatar_path):
                flash("Profile and password updated successfully")
            elif password_changed:
                flash("Password updated successfully")
            elif updates.get("phone") or updates.get("email") or avatar_path:
                flash("Profile updated successfully")
            else:
                flash("No changes made")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)

@app.route("/validate", methods=["POST"]) 
def validate():
    kind = request.form.get("kind")
    value = request.form.get("value", "").strip()
    ok = False
    if kind == "username":
        ok = is_valid_username(value) and get_user(value) == {}
    elif kind == "phone":
        ok = is_valid_phone(value)
    elif kind == "email":
        ok = is_valid_email(value)
    return {"ok": bool(ok)}

@app.route("/accounts", methods=["GET"]) 
def accounts():
    accs = list_accounts()
    return render_template("accounts.html", accounts=accs)

@app.route("/accounts/remove", methods=["POST"]) 
def accounts_remove():
    username = request.form.get("username", "").strip()
    if username:
        remove_account(username)
        flash("Account removed")
    return redirect(url_for("accounts"))

@app.route("/accounts/save_password", methods=["POST"]) 
def accounts_save_password():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if username and password:
        remember_account(username, saved_password=password)
        flash("Password saved for account")
    return redirect(url_for("accounts"))

@app.route("/accounts/clear_password", methods=["POST"]) 
def accounts_clear_password():
    username = request.form.get("username", "").strip()
    if username:
        remove_saved_password(username)
        flash("Saved password cleared")
    return redirect(url_for("accounts"))

@app.route("/accounts/ban", methods=["POST"]) 
@login_required
def accounts_ban():
    acting_username = session.get("user")
    acting = get_user(acting_username)
    role = (acting or {}).get("role", "").lower()
    if role != "admin":
        flash("Only admin accounts can ban users.", "error")
        return redirect(url_for("accounts"))
    username = request.form.get("username", "").strip()
    if username:
        if username == acting_username:
            flash("You cannot ban yourself.", "error")
        elif ban_user(username, acting_username):
            # Log user ban
            from utils.storage import add_audit_event
            import datetime
            add_audit_event({
                "kind": "user_management",
                "action": "user_banned",
                "username": acting_username,
                "timestamp": datetime.datetime.now().isoformat(),
                "details": {"banned_user": username}
            })
            
            flash(f"User '{username}' has been banned successfully.", "success")
        else:
            flash("Failed to ban user. User may not exist or you don't have permission.", "error")
    return redirect(url_for("accounts"))

@app.route("/users/manage")
@login_required
def manage_users():
    """User management page - only accessible by admins."""
    acting_username = session.get("user")
    acting = get_user(acting_username)
    role = (acting or {}).get("role", "").lower()
    
    if role != "admin":
        flash("Only admin accounts can access user management.", "error")
        return redirect(url_for("overview"))
    
    # Get all users
    users = list_users(limit=500)
    return render_template("manage_users.html", users=users, current_username=acting_username)

@app.route("/users/ban/<username>", methods=["POST"])
@login_required
def ban_user_route(username):
    """Ban a specific user - only accessible by admins."""
    acting_username = session.get("user")
    acting = get_user(acting_username)
    role = (acting or {}).get("role", "").lower()
    
    if role != "admin":
        flash("Only admin accounts can ban users.", "error")
        return redirect(url_for("overview"))
    
    if username == acting_username:
        flash("You cannot ban yourself.", "error")
    elif ban_user(username, acting_username):
        flash(f"User '{username}' has been banned successfully.", "success")
    else:
        flash("Failed to ban user. User may not exist or you don't have permission.", "error")
    
    return redirect(url_for("manage_users"))

@app.route("/audit")
@login_required
def audit_index():
    all_events = list_audit_events("", limit=200)
    kinds = sorted({e.get("kind") for e in all_events if e.get("kind")})
    session_info = get_current_audit_session_info()
    return render_template(
        "audit.html",
        events=all_events,
        kinds=kinds,
        filter_kind="",
        session_info=session_info,
    )

@app.route("/audit/<kind>")
@login_required
def audit_kind(kind):
    kind = (kind or "").strip()
    all_events = list_audit_events("", limit=200)
    events = [e for e in all_events if e.get("kind") == kind]
    kinds = sorted({e.get("kind") for e in all_events if e.get("kind")})
    session_info = get_current_audit_session_info()
    return render_template(
        "audit.html",
        events=events,
        kinds=kinds,
        filter_kind=kind,
        session_info=session_info,
    )

@app.route("/audit/archive", methods=["POST"]) 
@login_required
def audit_archive():
    acting = get_user(session.get("user"))
    role = (acting or {}).get("role", "").lower()
    if role not in {"admin", "auditor", "it_security"}:
        flash("Only admin, auditor, and IT security can archive audit logs.", "error")
        return redirect(url_for("audit_index"))
    any_login = archive_audit_logins()
    any_events = archive_audit_events()
    if any_login or any_events:
        flash("Audit logs archived.", "success")
    else:
        flash("No audit records to archive.", "info")
    return redirect(url_for("audit_index"))

@app.route("/audit/archive/view")
@login_required
def audit_archive_view():
    acting = get_user(session.get("user"))
    role = (acting or {}).get("role", "").lower()
    if role not in {"admin", "auditor"}:
        flash("Only admin and auditor can view archived audits.", "error")
        return redirect(url_for("overview"))
    login_archives = list_audit_login_archives()
    event_archives = list_audit_event_archives()
    return render_template(
        "audit_archive.html",
        login_archives=login_archives,
        event_archives=event_archives,
    )

@app.route("/audit/archive/restore", methods=["POST"]) 
@login_required
def audit_archive_restore():
    acting = get_user(session.get("user"))
    role = (acting or {}).get("role", "").lower()
    if role not in {"admin", "auditor", "it_security"}:
        flash("Only admin, auditor, and IT security can restore archived logs.", "error")
        return redirect(url_for("audit_archive_view"))
    any_login = restore_audit_logins()
    any_events = restore_audit_events()
    if any_login or any_events:
        flash("Archived audit logs restored to active view.", "success")
    else:
        flash("No archived records to restore.", "info")
    return redirect(url_for("audit_index"))

@app.route("/audit/new-session", methods=["POST"])
@login_required
def audit_new_session():
    """Start a new audit session by archiving current logs and beginning fresh tracking."""
    acting_username = session.get("user")
    acting = get_user(acting_username)
    role = (acting or {}).get("role", "").lower()
    
    if role not in {"admin", "auditor"}:
        flash("Only admin and auditor can start new audit sessions.", "error")
        return redirect(url_for("audit_index"))
    
    # Archive current logs
    any_login = archive_audit_logins()
    any_events = archive_audit_events()
    
    # Log the session start event
    from utils.storage import add_audit_event
    import datetime
    add_audit_event({
        "kind": "audit_management",
        "action": "new_session_started",
        "username": acting_username,
        "timestamp": datetime.datetime.now().isoformat(),
        "details": {
            "session_started_by": acting_username,
            "previous_logs_archived": any_login or any_events
        }
    })
    
    if any_login or any_events:
        flash("New audit session started. Previous logs have been archived.", "success")
    else:
        flash("New audit session started. No previous logs to archive.", "info")
    
    return redirect(url_for("audit_index"))

def clear_phi_session_data():
    """
    ✅ CORRECT: Clear PHI authentication session when user navigates away.
    This ensures users must re-authenticate to view PHI data.
    Server handles encryption automatically - no manual encryption needed.
    """
    # Clear PHI authentication flags
    session.pop("pin_ok", None)
    session.pop("pin_ok_until", None)
    session.pop("bio_ok", None)
    
    # Clear any temporary PHI session data
    session.pop("patients_db_decrypted", None)
    session.pop("diagnoses_decrypted", None)
    session.pop("prescriptions_decrypted", None)
    session.pop("appointments_decrypted", None)

@app.route("/clear-phi-session", methods=["POST"])
@login_required
def clear_phi_session():
    """
    ✅ CORRECT: Clear PHI authentication when user navigates away.
    Server handles encryption automatically - this just clears session auth.
    """
    clear_phi_session_data()
    
    # Log session clearing event
    from utils.storage import add_audit_event
    import datetime
    add_audit_event({
        "kind": "data_access",
        "action": "clear_phi_session",
        "username": session.get("user", "unknown"),
        "timestamp": datetime.datetime.now().isoformat(),
        "details": {"trigger": "navigation_away", "reason": "phi_session_timeout"}
    })
    
    return {"status": "success", "message": "PHI session cleared - re-authentication required"}

@app.route("/logout")
@login_required
def logout():
    # Clear PHI session data before logout (server handles encryption automatically)
    clear_phi_session_data()
    
    # Log logout event
    from utils.storage import add_audit_event
    import datetime
    add_audit_event({
        "kind": "authentication",
        "action": "logout",
        "username": session.get("user", "unknown"),
        "timestamp": datetime.datetime.now().isoformat(),
        "details": {"auto_encrypted": True}
    })
    
    session.clear()
    flash("Logged out successfully. All data has been automatically encrypted.", "info")
    return redirect(url_for("login"))

@app.context_processor
def inject_user():
    u = None
    if session.get("user"):
        try:
            u = get_user(session.get("user"))
        except Exception:
            u = None
    return {"current_user": u}

@app.route("/dashboard")
@login_required
def dashboard():
    # Clear PHI session when navigating to dashboard (require re-auth for PHI)
    clear_phi_session_data()
    # Summary cards
    try:
        doctors = len(list_records("doctors"))
    except Exception:
        doctors = 0
    try:
        patients = len(list_records("patients_db"))
    except Exception:
        patients = 0
    # Nurses: count users with nurse role
    try:
        nurse_users = list_users(limit=500)
        nurses = sum(1 for u in nurse_users if (u.get("role") or "").lower() == "nurse")
    except Exception:
        nurses = 0

    cards = {
        "doctors": doctors,
        "patients": patients,
        "nurses": nurses,
    }

    # Incidents by Status for bar chart
    bar_labels = []
    bar_values = []
    try:
        incidents = list_records("incidents")
        counts = {}
        for row in incidents:
            status = (row.get("Status") or "Unknown").strip() or "Unknown"
            counts[status] = counts.get(status, 0) + 1
        for k in sorted(counts.keys()):
            bar_labels.append(k)
            bar_values.append(counts[k])
    except Exception:
        pass

    # Threat severity donut chart based on Impact
    doughnut_labels = []
    doughnut_values = []
    try:
        threats = list_records("threats")
        sev_counts = {}
        for row in threats:
            impact = (row.get("Impact") or "").strip()
            # Map impact directly; fallback to "Unknown"
            key = impact or "Unknown"
            sev_counts[key] = sev_counts.get(key, 0) + 1
        for k in sorted(sev_counts.keys()):
            doughnut_labels.append(k)
            doughnut_values.append(sev_counts[k])
    except Exception:
        pass

    # Users for bottom table
    try:
        users = list_users(limit=50)
    except Exception:
        users = []

    return render_template(
        "dashboard.html",
        cards=cards,
        bar_labels=bar_labels,
        bar_values=bar_values,
        doughnut_labels=doughnut_labels,
        doughnut_values=doughnut_values,
        users=users,
    )

@app.route("/overview")
@login_required
def overview():
    # Clear PHI session when navigating to overview (require re-auth for PHI)
    clear_phi_session_data()
    
    def capture(fn):
        buf = io.StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            fn()
        finally:
            sys.stdout = old
        return buf.getvalue()

    profile_text = capture(show_company_profile)
    controls_text = capture(show_security_controls)
    compliance_text = capture(show_compliance)
    return render_template("overview.html", profile_text=profile_text, controls_text=controls_text, compliance_text=compliance_text)

KIND_COLUMNS = {
    "assets": ["Asset Name", "Type", "Value", "Owner", "Security Classification"],
    "threats": ["Threat", "Vulnerability", "Likelihood", "Impact", "Countermeasure"],
    "incidents": ["Incident Type", "Date & Time", "Affected Systems", "Actions Taken", "Status"],
    "bia": ["Asset", "Threat Scenario", "Financial Impact", "Operational Impact", "Recovery Strategy"],
    # JSON demo patients list (separate from MySQL patients_db)
    "patients": ["Patient Name", "Date of Birth", "Phone Number", "Blood Type", "Amount", "Diagnosis"],
    # MySQL-backed hospital modules
    "doctors": ["ID", "Name", "Specialty", "Contact"],
    "appointments": ["Appointment ID", "Patient Name", "Doctor Name", "Date", "Time", "Status"],
    "patients_db": ["Patient ID", "First Name", "Last Name", "Age", "Gender", "Contact", "Allergies"],
    "diagnoses": ["Diagnosis ID", "Patient Name", "Doctor Name", "Diagnosis", "Date", "Notes"],
    "prescriptions": ["Prescription ID", "Patient Name", "Doctor Name", "Medications", "Date", "Notes"],
    "medical_store": ["Item ID", "Name", "Quantity", "Unit Price", "Expiration Date", "Notes"],
}

SEED_DATA = {
    "assets": default_assets,
    "threats": default_threats,
    "bia": default_bia,
    "incidents": [],
    "patients": [],
}

# 🏥 HEALTHCARE RBAC - PROPER SECURITY MODEL
# ✅ Roles control PERMISSIONS, NOT encryption/decryption
# ✅ Server handles ALL encryption/decryption automatically
# ✅ Users never directly encrypt/decrypt data

def can_view_phi_data(username: str, kind: str) -> bool:
    """
    ✅ CORRECT: Check if user role can VIEW decrypted PHI data.
    Server will automatically decrypt for authorized users.
    """
    if not username:
        return False
    role = (get_user_role(username) or "").lower()

    # ✅ ADMIN: Can view system data but NOT patient PHI unless explicitly granted
    if role == "admin":
        # Admins can see system data but need explicit permission for PHI
        return kind in {"assets", "threats", "bia", "incidents"}

    # ✅ DOCTOR: Can view ALL patient PHI data (server decrypts automatically)
    if role == "doctor":
        return kind in {"patients_db", "diagnoses", "prescriptions", "appointments", "doctors", "incidents"}

    # ✅ NURSE: Can view basic patient info and medical store
    if role == "nurse":
        return kind in {"patients_db", "appointments", "medical_store", "incidents"}

    # ✅ PHARMACIST: Can view prescriptions and inventory
    if role == "pharmacist":
        return kind in {"prescriptions", "medical_store", "patients_db", "incidents"}

    # ✅ AUDITOR: Can view logs but NO patient PHI unless specifically granted
    if role == "auditor":
        return kind in {"incidents"}  # Only non-PHI data

    # ✅ IT SECURITY: NO access to patient PHI (security separation)
    if role == "it_security":
        return kind in {"assets", "threats", "bia", "incidents"}

    # ✅ RECEPTIONIST: Basic appointment and patient contact info only
    if role == "receptionist":
        return kind in {"appointments", "patients_db"}  # Limited patient info

    # ✅ ASSET MANAGER: Can view assets
    if role == "asset_manager":
        return kind in {"assets", "incidents"}

    # ✅ INVENTORY STAFF: Can view medical store
    if role == "inventory":
        return kind in {"medical_store", "incidents"}

    # ✅ PATIENTS ROLE: Can view medical store, patients, and doctors (read-only)
    if role == "patients":
        return kind in {"medical_store", "patients_db", "doctors", "incidents"}

    # ✅ OTHER ROLE: Can view medical store, patients, and doctors (read-only)
    if role == "other":
        return kind in {"medical_store", "patients_db", "doctors", "incidents"}

    # ✅ PATIENT/VISITOR: No general access (would need patient-specific check)
    return False

def can_edit_kind(username: str, kind: str) -> bool:
    """
    ✅ CORRECT: Check if user role can EDIT data.
    Server handles encryption automatically when saving.
    """
    if not username:
        return False
    role = (get_user_role(username) or "").lower()

    # ✅ ADMIN: Can edit system data but NOT patient PHI unless explicitly granted
    if role == "admin":
        return kind in {"assets", "threats", "bia", "incidents", "doctors"}  # No direct PHI editing

    # ✅ DOCTOR: Can edit medical records (server encrypts automatically)
    if role == "doctor":
        return kind in {"patients_db", "diagnoses", "prescriptions", "appointments", "doctors", "incidents"}

    # ✅ NURSE: Can edit basic patient info and medical store (with PIN verification)
    if role == "nurse":
        return kind in {"patients_db", "incidents", "medical_store"}

    # ✅ PHARMACIST: Can edit prescriptions and inventory
    if role == "pharmacist":
        return kind in {"prescriptions", "medical_store", "incidents"}

    # ✅ INVENTORY STAFF: Medical store only
    if role == "inventory":
        return kind in {"medical_store", "incidents"}

    # ✅ IT SECURITY: System security data only (NO patient PHI)
    if role == "it_security":
        return kind in {"assets", "threats", "bia", "incidents"}

    # ✅ RECEPTIONIST: Appointments only
    if role == "receptionist":
        return kind in {"appointments", "incidents"}

    # ✅ ASSET MANAGER: Can access assets
    if role == "asset_manager":
        return kind in {"assets", "incidents"}

    # ✅ AUDITOR: Read-only (no editing)
    if role == "auditor":
        return False

    # ✅ PATIENT/VISITOR: No editing access
    return False

def requires_phi_authentication(username: str, kind: str) -> bool:
    """
    ✅ CORRECT: Check if accessing this data requires additional authentication.
    Used for PIN/biometric verification before server decrypts PHI data.
    """
    if not username:
        return True
    
    # PHI data always requires additional authentication
    phi_modules = {"patients_db", "diagnoses", "prescriptions", "appointments"}
    
    if kind in phi_modules:
        role = (get_user_role(username) or "").lower()
        
        # Doctors and nurses need PIN/biometric for PHI access
        if role in {"doctor", "nurse", "pharmacist"}:
            return True
    
    return False

@app.route("/records/<kind>")
@login_required
def list_view(kind):
    if kind not in KIND_COLUMNS:
        return ("Unknown kind", 404)
    user = session.get("user")
    edit_mode = request.args.get("edit") == "1"
    
    # ✅ STEP 1: Check if user has permission to VIEW this data type
    if not can_view_phi_data(user, kind):
        flash("You do not have permission to view this data.", "error")
        return redirect(url_for("overview"))
    
    # ✅ STEP 2: Check if PHI authentication is required
    # Server will automatically decrypt ONLY if user is authenticated
    needs_phi_auth = requires_phi_authentication(user, kind)
    phi_authenticated = False
    
    if needs_phi_auth:
        now = int(time.time())
        if (session.get("pin_ok") and now < int(session.get("pin_ok_until") or 0)) or session.get("bio_ok"):
            phi_authenticated = True
    else:
        phi_authenticated = True  # No PHI auth needed for non-PHI data
    
    # Log data access for sensitive modules
    if kind in ["patients_db", "diagnoses", "prescriptions", "appointments", "medical_store"]:
        from utils.storage import add_audit_event
        import datetime
        
        # Special logging for nurse access to medical_store
        user_role = (get_user(user) or {}).get("role", "").lower()
        action_details = {"module": kind}
        
        if kind == "medical_store" and user_role == "nurse":
            action_details.update({
                "nurse_access": True,
                "edit_mode": edit_mode,
                "pin_verified": session.get("pin_ok", False)
            })
        
        add_audit_event({
            "kind": "data_access",
            "action": "view_records",
            "username": user,
            "timestamp": datetime.datetime.now().isoformat(),
            "details": action_details
        })
    
    # ✅ STEP 3: Server automatically decrypts data for authorized users
    # Only decrypt if user has proper authentication for PHI data
    decrypt_data = phi_authenticated and can_view_phi_data(user, kind)
    decrypt_clinical_data = phi_authenticated and can_view_phi_data(user, kind)
    
    # ✅ Server handles decryption automatically based on permissions
    items = list_records(kind, decrypt_patients_db=decrypt_data, decrypt_clinical=decrypt_clinical_data)
    extra_cols = []
    extra_rows = []
    nurse_rows = []
    if kind == "threats":
        pass
    # Additional nurse table when viewing doctors
    try:
        if kind == "doctors":
            nurse_users = list_users(limit=500)
            nurse_rows = [u for u in nurse_users if (u.get("role") or "").lower() == "nurse"]
    except Exception:
        nurse_rows = []
    user_can_edit = can_edit_kind(user, kind)
    
    # Require PIN/biometric verification when entering edit mode for clinical modules
    # Also require PIN verification for nurses accessing medical_store in edit mode
    user_role = (get_user(user) or {}).get("role", "").lower()
    requires_pin_verification = False
    
    if edit_mode and kind in ["patients_db", "appointments", "diagnoses", "prescriptions", "doctors"]:
        requires_pin_verification = True
    elif edit_mode and kind == "medical_store" and user_role == "nurse":
        requires_pin_verification = True
    
    if requires_pin_verification:
        now = int(time.time())
        strong_ok = False
        if session.get("pin_ok") and now < int(session.get("pin_ok_until") or 0):
            strong_ok = True
        if session.get("bio_ok"):
            strong_ok = True
        if not strong_ok:
            return redirect(url_for("verify_pin_route", next=url_for("list_view", kind=kind) + "?edit=1"))
    
    allow_delete = user_can_edit and kind in {"assets", "threats", "incidents", "bia", "patients", "patients_db", "appointments", "diagnoses", "prescriptions", "medical_store", "doctors"}
    return render_template(
        "list.html",
        kind=kind,
        columns=KIND_COLUMNS[kind],
        items=items,
        can_edit=user_can_edit,
        extra_columns=extra_cols,
        extra_rows=extra_rows,
        edit_mode=edit_mode,
        allow_delete=allow_delete,
        nurse_rows=nurse_rows,
    )

@app.route("/records/<kind>/add", methods=["GET", "POST"]) 
@login_required
def add_view(kind):
    if kind not in KIND_COLUMNS:
        return ("Unknown kind", 404)
    if not can_edit_kind(session.get("user"), kind):
        flash("You do not have permission to add records.", "error")
        return redirect(url_for("list_view", kind=kind))
    
    # Require recent PIN OR biometric verification before modifying data
    # Special requirement for nurses accessing medical_store
    user_role = (get_user(session.get("user")) or {}).get("role", "").lower()
    requires_pin_verification = True
    
    # For nurses accessing medical_store, always require PIN verification
    if kind == "medical_store" and user_role == "nurse":
        requires_pin_verification = True
    
    if requires_pin_verification:
        now = int(time.time())
        strong_ok = False
        if session.get("pin_ok") and now < int(session.get("pin_ok_until") or 0):
            strong_ok = True
        if session.get("bio_ok"):
            strong_ok = True
        if not strong_ok:
            return redirect(url_for("verify_pin_route", next=url_for("add_view", kind=kind)))
    
    columns = KIND_COLUMNS[kind]
    
    # Get doctor and patient options for clinical modules
    doctor_options = []
    patient_options = []
    patient_first_options = []
    patient_last_options = []
    
    if kind in ["appointments", "diagnoses", "prescriptions"]:
        try:
            # Get doctors
            doctors = list_records("doctors")
            doctor_options = [d.get('Name', '').strip() for d in doctors if d.get('Name', '').strip()]
            
            # Get patients with decrypted names for dropdown display
            patients = list_records("patients_db", decrypt_patients_db=True)
            patient_options = [f"{p.get('First Name', '')} {p.get('Last Name', '')}".strip() for p in patients if p.get('First Name')]
            patient_first_options = sorted(list(set([p.get('First Name', '').strip() for p in patients if p.get('First Name')])))
            patient_last_options = sorted(list(set([p.get('Last Name', '').strip() for p in patients if p.get('Last Name')])))
            
            # Validate that we have both doctors and patients
            if not doctor_options:
                flash(f"No doctors found in the system. Please add doctors before creating {kind}.", "warning")
            if not patient_first_options:
                flash(f"No patients found in the system. Please add patients before creating {kind}.", "warning")
        except Exception as e:
            logger.error(f"Error loading {kind} options: {e}")
            flash("Error loading doctors and patients. Please try again.", "error")
    
    if request.method == "POST":
        try:
            new_item = {col: request.form.get(col, "").strip() for col in columns}
            
            # Validate required fields (skip ID fields as they can be auto-generated)
            id_fields = ["ID", "Patient ID", "Appointment ID", "Diagnosis ID", "Prescription ID", "Item ID"]
            missing_fields = [col for col in columns if not new_item.get(col) and col not in id_fields]
            
            # Special validation for clinical modules
            if kind in ["appointments", "diagnoses", "prescriptions", "patients_db", "doctors"] and missing_fields:
                flash(f"Missing required fields: {', '.join(missing_fields)}", "error")
                return render_template("edit.html", kind=kind, columns=columns, values=new_item, 
                                     doctor_options=doctor_options, patient_options=patient_options,
                                     patient_first_options=patient_first_options, patient_last_options=patient_last_options)
            
            # ✅ ENCRYPT SENSITIVE PHI DATA for JSON-based patients
            if kind == "patients":
                # ✅ ENCRYPT: Diagnosis (sensitive medical information)
                if new_item.get("Diagnosis"):
                    new_item["Diagnosis"] = encrypt_sensitive_data(new_item.get("Diagnosis", ""))
                # ✅ ENCRYPT: Blood Type (sensitive medical information)
                if new_item.get("Blood Type"):
                    new_item["Blood Type"] = encrypt_sensitive_data(new_item.get("Blood Type", ""))
                # ✅ ENCRYPT: Amount (financial PHI)
                if new_item.get("Amount"):
                    new_item["Amount"] = encrypt_sensitive_data(new_item.get("Amount", ""))
                # ✅ ENCRYPT: Phone Number (patient identifier PHI)
                if new_item.get("Phone Number"):
                    new_item["Phone Number"] = encrypt_sensitive_data(new_item.get("Phone Number", ""))
            
            # Handle MySQL-backed modules
            clinical_mysql_kinds = {"patients_db", "appointments", "diagnoses", "prescriptions", "medical_store", "doctors"}
            if kind in clinical_mysql_kinds:
                ok = add_mysql_record(kind, new_item, username=session.get("user", "system"))
                if not ok:
                    logger.error(f"Failed to add {kind} record: {new_item}")
                    if kind in ["appointments", "diagnoses", "prescriptions"]:
                        flash(f"Failed to add {kind[:-1]}. Please ensure the patient and doctor exist in the system.", "error")
                    elif kind == "doctors":
                        flash("Failed to add doctor. Please check that all required fields are filled correctly.", "error")
                    elif kind == "patients_db":
                        flash("Failed to add patient. Please check that all required fields are filled correctly.", "error")
                    else:
                        flash("Failed to add record to database. Please check your input and try again.", "error")
                    return render_template("edit.html", kind=kind, columns=columns, values=new_item,
                                         doctor_options=doctor_options, patient_options=patient_options,
                                         patient_first_options=patient_first_options, patient_last_options=patient_last_options)
                else:
                    flash("Record added successfully.", "success")
                return redirect(url_for("list_view", kind=kind))
            
            # Handle JSON-based modules
            items = list_records(kind)
            items.append(new_item)
            save_records(kind, items)
            flash("Record added successfully.", "success")
            return redirect(url_for("list_view", kind=kind))
            
        except Exception as e:
            logger.error(f"Error adding {kind} record: {str(e)}")
            flash(f"An error occurred while adding the record: {str(e)}", "error")
            return render_template("edit.html", kind=kind, columns=columns, 
                                 values=new_item if 'new_item' in locals() else {},
                                 doctor_options=doctor_options, patient_options=patient_options,
                                 patient_first_options=patient_first_options, patient_last_options=patient_last_options)
    
    return render_template("edit.html", kind=kind, columns=columns, values={},
                         doctor_options=doctor_options, patient_options=patient_options,
                         patient_first_options=patient_first_options, patient_last_options=patient_last_options)

@app.route("/records/<kind>/edit/<int:index>", methods=["GET", "POST"]) 
@login_required
def edit_view(kind, index):
    if kind not in KIND_COLUMNS:
        return ("Unknown kind", 404)
    if not can_edit_kind(session.get("user"), kind):
        flash("You do not have permission to edit records.", "error")
        return redirect(url_for("list_view", kind=kind))
    
    # Require recent PIN OR biometric verification before modifying data
    # Special requirement for nurses accessing medical_store
    user_role = (get_user(session.get("user")) or {}).get("role", "").lower()
    requires_pin_verification = True
    
    # For nurses accessing medical_store, always require PIN verification
    if kind == "medical_store" and user_role == "nurse":
        requires_pin_verification = True
    
    if requires_pin_verification:
        now = int(time.time())
        strong_ok = False
        if session.get("pin_ok") and now < int(session.get("pin_ok_until") or 0):
            strong_ok = True
        if session.get("bio_ok"):
            strong_ok = True
        if not strong_ok:
            return redirect(url_for("verify_pin_route", next=url_for("edit_view", kind=kind, index=index)))
    
    columns = KIND_COLUMNS[kind]
    
    # Get records with proper decryption for display
    # For editing, we always need decrypted data to display properly
    decrypt_data = True
    if kind == "patients_db":
        decrypt_data = True  # Always decrypt for editing
    elif kind in ["diagnoses", "prescriptions", "appointments"]:
        decrypt_data = True  # Always decrypt for editing
    
    items = list_records(kind, decrypt_patients_db=decrypt_data, decrypt_clinical=decrypt_data)
    if index < 0 or index >= len(items):
        return ("Not found", 404)
    
    # Get doctor and patient options for clinical modules
    doctor_options = []
    patient_options = []
    patient_first_options = []
    patient_last_options = []
    
    if kind in ["appointments", "diagnoses", "prescriptions"]:
        try:
            # Get doctors
            doctors = list_records("doctors")
            doctor_options = [d.get('Name', '').strip() for d in doctors if d.get('Name', '').strip()]
            
            # Get patients with decrypted names for dropdown display
            patients = list_records("patients_db", decrypt_patients_db=True)
            patient_options = [f"{p.get('First Name', '')} {p.get('Last Name', '')}".strip() for p in patients if p.get('First Name')]
            patient_first_options = sorted(list(set([p.get('First Name', '').strip() for p in patients if p.get('First Name')])))
            patient_last_options = sorted(list(set([p.get('Last Name', '').strip() for p in patients if p.get('Last Name')])))
            
            # Validate that we have both doctors and patients
            if not doctor_options:
                flash(f"No doctors found in the system. Please add doctors before editing {kind}.", "warning")
            if not patient_first_options:
                flash(f"No patients found in the system. Please add patients before editing {kind}.", "warning")
        except Exception as e:
            logger.error(f"Error loading {kind} options in edit: {e}")
            flash("Error loading doctors and patients. Please try again.", "error")
    
    if request.method == "POST":
        action = request.form.get("action", "")
        
        # Handle decrypt action for individual records
        if action == "decrypt":
            decrypted_values = dict(items[index])
            
            if kind == "patients_db":
                # ✅ DECRYPT PHI DATA for authorized viewing
                # Decrypt Last Name (PHI)
                raw_last_name = decrypted_values.get("Last Name", "")
                if raw_last_name and is_encrypted_data(str(raw_last_name)):
                    decrypted_values["Last Name"] = decrypt_sensitive_data(str(raw_last_name))
                
                # Decrypt Contact (PHI)
                raw_contact = decrypted_values.get("Contact", "")
                if raw_contact and is_encrypted_data(str(raw_contact)):
                    decrypted_values["Contact"] = decrypt_sensitive_data(str(raw_contact))
                
                # Decrypt Allergies (sensitive medical data)
                raw_allergies = decrypted_values.get("Allergies", "")
                if raw_allergies and is_encrypted_data(str(raw_allergies)):
                    decrypted_values["Allergies"] = decrypt_sensitive_data(str(raw_allergies))
            
            elif kind == "appointments":
                # Decrypt Patient Name
                raw_patient = decrypted_values.get("Patient Name", "")
                if raw_patient and str(raw_patient).startswith("gAAAA"):
                    try:
                        decrypted_values["Patient Name"] = decrypt_text(str(raw_patient))
                    except Exception:
                        pass
                # Decrypt Doctor Name
                raw_doctor = decrypted_values.get("Doctor Name", "")
                if raw_doctor and str(raw_doctor).startswith("gAAAA"):
                    try:
                        decrypted_values["Doctor Name"] = decrypt_text(str(raw_doctor))
                    except Exception:
                        pass
                # Decrypt Status
                raw_status = decrypted_values.get("Status", "")
                if raw_status and str(raw_status).startswith("gAAAA"):
                    try:
                        decrypted_values["Status"] = decrypt_text(str(raw_status))
                    except Exception:
                        pass
            
            elif kind == "diagnoses":
                # Decrypt Diagnosis
                raw_diagnosis = decrypted_values.get("Diagnosis", "")
                if raw_diagnosis and str(raw_diagnosis).startswith("gAAAA"):
                    try:
                        decrypted_values["Diagnosis"] = decrypt_text(str(raw_diagnosis))
                    except Exception:
                        pass
                # Decrypt Notes
                raw_notes = decrypted_values.get("Notes", "")
                if raw_notes and str(raw_notes).startswith("gAAAA"):
                    try:
                        decrypted_values["Notes"] = decrypt_text(str(raw_notes))
                    except Exception:
                        pass
            
            elif kind == "prescriptions":
                # Decrypt Medications
                raw_medications = decrypted_values.get("Medications", "")
                if raw_medications and str(raw_medications).startswith("gAAAA"):
                    try:
                        decrypted_values["Medications"] = decrypt_text(str(raw_medications))
                    except Exception:
                        pass
                # Decrypt Notes
                raw_notes = decrypted_values.get("Notes", "")
                if raw_notes and str(raw_notes).startswith("gAAAA"):
                    try:
                        decrypted_values["Notes"] = decrypt_text(str(raw_notes))
                    except Exception:
                        pass
            
            return render_template("edit.html", kind=kind, columns=columns, values=decrypted_values, 
                                 index=index, decrypted=True, doctor_options=doctor_options, 
                                 patient_options=patient_options, patient_first_options=patient_first_options, 
                                 patient_last_options=patient_last_options)
        
        # Handle save action
        try:
            updated = {col: request.form.get(col, "").strip() for col in columns}
            
            # For clinical records with fixed patient fields, ensure patient name is preserved correctly
            if kind in ["appointments", "diagnoses", "prescriptions"] and "Patient Name" in updated:
                # Ensure patient name is not encrypted when passed to update function
                patient_name = updated.get("Patient Name", "")
                if patient_name and str(patient_name).startswith("gAAAA"):
                    try:
                        updated["Patient Name"] = decrypt_text(str(patient_name))
                        logger.info(f"Decrypted patient name for {kind} update: {updated['Patient Name']}")
                    except Exception as e:
                        logger.warning(f"Failed to decrypt patient name: {e}")
                        pass  # Keep as is if decryption fails
                else:
                    logger.info(f"Patient name for {kind} update (already decrypted): {patient_name}")
                
                # Validate patient name format (should have first and last name)
                if patient_name and len(patient_name.split()) < 2:
                    flash(f"Invalid patient name format. Please ensure both first and last names are provided.", "error")
                    return render_template("edit.html", kind=kind, columns=columns, values=updated,
                                         index=index, decrypted=False, doctor_options=doctor_options,
                                         patient_options=patient_options, patient_first_options=patient_first_options,
                                         patient_last_options=patient_last_options)
            
            # Validate required fields (skip ID fields as they're auto-generated)
            id_fields = ["ID", "Patient ID", "Appointment ID", "Diagnosis ID", "Prescription ID", "Item ID"]
            missing_fields = [col for col in columns if not updated.get(col) and col not in id_fields]
            if missing_fields and kind in ["appointments", "diagnoses", "prescriptions", "patients_db", "doctors"]:
                flash(f"Missing required fields: {', '.join(missing_fields)}", "error")
                return render_template("edit.html", kind=kind, columns=columns, values=updated, 
                                     index=index, decrypted=False, doctor_options=doctor_options,
                                     patient_options=patient_options, patient_first_options=patient_first_options,
                                     patient_last_options=patient_last_options)
            
            # Handle JSON-based patients encryption
            if kind == "patients":
                if updated.get("Diagnosis") and not str(updated.get("Diagnosis", "")).startswith("gAAAA"):
                    updated["Diagnosis"] = encrypt_text(updated.get("Diagnosis", ""))
                if updated.get("Blood Type") and not str(updated.get("Blood Type", "")).startswith("gAAAA"):
                    updated["Blood Type"] = encrypt_text(updated.get("Blood Type", ""))
                if updated.get("Amount") and not str(updated.get("Amount", "")).startswith("gAAAA"):
                    updated["Amount"] = encrypt_text(updated.get("Amount", ""))
                if updated.get("Phone Number") and not str(updated.get("Phone Number", "")).startswith("gAAAA"):
                    updated["Phone Number"] = encrypt_text(updated.get("Phone Number", ""))
            
            # Handle MySQL-backed modules
            clinical_mysql_kinds = {"patients_db", "appointments", "diagnoses", "prescriptions", "medical_store", "doctors"}
            if kind in clinical_mysql_kinds:
                id_key_map = {
                    "patients_db": "Patient ID",
                    "appointments": "Appointment ID",
                    "diagnoses": "Diagnosis ID",
                    "prescriptions": "Prescription ID",
                    "medical_store": "Item ID",
                    "doctors": "ID",
                }
                id_key = id_key_map.get(kind)
                raw_id = items[index].get(id_key) if id_key else None
                try:
                    db_id = int(raw_id) if raw_id is not None else 0
                except Exception:
                    db_id = 0
                
                if not db_id:
                    flash("Invalid record identifier.", "error")
                    return redirect(url_for("list_view", kind=kind))
                
                # Log the update attempt for debugging
                logger.info(f"Attempting to update {kind} record ID {db_id} with data: {updated}")
                
                # Special logging for appointment status updates
                if kind == "appointments" and "Status" in updated:
                    status_value = updated['Status']
                    valid_statuses = ['Scheduled', 'Completed', 'Canceled']
                    if status_value not in valid_statuses:
                        logger.warning(f"Invalid appointment status: {status_value}. Valid options: {valid_statuses}")
                        flash(f"Invalid status. Please select from: {', '.join(valid_statuses)}", "error")
                        return render_template("edit.html", kind=kind, columns=columns, values=updated,
                                             index=index, decrypted=False, doctor_options=doctor_options,
                                             patient_options=patient_options, patient_first_options=patient_first_options,
                                             patient_last_options=patient_last_options)
                    logger.info(f"Updating appointment status to: {status_value}")
                
                ok = update_mysql_record(kind, db_id, updated, username=session.get("user", "system"))
                if not ok:
                    logger.error(f"Failed to update {kind} record ID {db_id}: {updated}")
                    if kind in ["appointments", "diagnoses", "prescriptions"]:
                        flash(f"Failed to update {kind[:-1]}. Please ensure the patient and doctor exist in the system.", "error")
                    else:
                        flash("Failed to update record in database. Please check your input and try again.", "error")
                    return render_template("edit.html", kind=kind, columns=columns, values=updated,
                                         index=index, decrypted=False, doctor_options=doctor_options,
                                         patient_options=patient_options, patient_first_options=patient_first_options,
                                         patient_last_options=patient_last_options)
                else:
                    logger.info(f"Successfully updated {kind} record ID {db_id}")
                    flash("Record updated successfully.", "success")
                return redirect(url_for("list_view", kind=kind))
            
            # Handle JSON-based modules
            items[index] = updated
            save_records(kind, items)
            flash("Record updated successfully.", "success")
            return redirect(url_for("list_view", kind=kind))
            
        except Exception as e:
            logger.error(f"Error updating {kind} record: {str(e)}")
            flash(f"An error occurred while updating the record: {str(e)}", "error")
            return render_template("edit.html", kind=kind, columns=columns, 
                                 values=updated if 'updated' in locals() else items[index],
                                 index=index, decrypted=False, doctor_options=doctor_options,
                                 patient_options=patient_options, patient_first_options=patient_first_options,
                                 patient_last_options=patient_last_options)
    
    return render_template("edit.html", kind=kind, columns=columns, values=items[index], 
                         index=index, decrypted=False, doctor_options=doctor_options, 
                         patient_options=patient_options, patient_first_options=patient_first_options,
                         patient_last_options=patient_last_options)

@app.route("/records/<kind>/delete/<int:index>", methods=["POST"]) 
@login_required
def delete_view(kind, index):
    if kind not in KIND_COLUMNS:
        return ("Unknown kind", 404)
    if not can_edit_kind(session.get("user"), kind):
        flash("You do not have permission to delete records.", "error")
        return redirect(url_for("list_view", kind=kind))
    
    # Require recent PIN OR biometric verification before modifying data
    # Special requirement for nurses accessing medical_store
    user_role = (get_user(session.get("user")) or {}).get("role", "").lower()
    requires_pin_verification = True
    
    # For nurses accessing medical_store, always require PIN verification
    if kind == "medical_store" and user_role == "nurse":
        requires_pin_verification = True
    
    if requires_pin_verification:
        now = int(time.time())
        strong_ok = False
        if session.get("pin_ok") and now < int(session.get("pin_ok_until") or 0):
            strong_ok = True
        if session.get("bio_ok"):
            strong_ok = True
        if not strong_ok:
            return redirect(url_for("verify_pin_route", next=url_for("list_view", kind=kind)))
    
    items = list_records(kind)
    if 0 <= index < len(items):
        try:
            # Handle MySQL-backed modules
            clinical_mysql_kinds = {"patients_db", "appointments", "diagnoses", "prescriptions", "medical_store", "doctors"}
            if kind in clinical_mysql_kinds:
                id_key_map = {
                    "patients_db": "Patient ID",
                    "appointments": "Appointment ID",
                    "diagnoses": "Diagnosis ID",
                    "prescriptions": "Prescription ID",
                    "medical_store": "Item ID",
                    "doctors": "ID",
                }
                id_key = id_key_map.get(kind)
                raw_id = items[index].get(id_key) if id_key else None
                try:
                    db_id = int(raw_id) if raw_id is not None else 0
                except Exception:
                    db_id = 0
                
                if not db_id:
                    flash("Invalid record identifier.", "error")
                else:
                    ok = delete_mysql_record(kind, db_id, username=session.get("user", "system"))
                    if not ok:
                        logger.error(f"Failed to delete {kind} record with ID {db_id}")
                        flash("Failed to delete record from database.", "error")
                    else:
                        flash("Record deleted successfully.", "success")
            else:
                # Handle JSON-based modules
                del items[index]
                save_records(kind, items)
                flash("Record deleted successfully.", "success")
        except Exception as e:
            logger.error(f"Error deleting {kind} record: {str(e)}")
            flash(f"An error occurred while deleting the record: {str(e)}", "error")
    else:
        flash("Record not found.", "error")
    
    return redirect(url_for("list_view", kind=kind))

@app.route("/records/<kind>/export.csv")
@login_required
def export_csv(kind):
    if kind not in KIND_COLUMNS:
        return ("Unknown kind", 404)
    items = list_records(kind)
    columns = KIND_COLUMNS[kind]
    
    # Calculate column widths
    col_widths = {}
    for col in columns:
        col_widths[col] = len(col)
    
    for item in items:
        for col in columns:
            value = str(item.get(col, ""))
            col_widths[col] = max(col_widths[col], len(value))
    
    # Build the table
    output = io.StringIO()
    
    # Header row
    header_parts = []
    for col in columns:
        header_parts.append(col.ljust(col_widths[col]))
    output.write(" | ".join(header_parts) + "\n")
    
    # Separator line
    separator_parts = []
    for col in columns:
        separator_parts.append("-" * col_widths[col])
    output.write("-+-".join(separator_parts) + "\n")
    
    # Data rows
    for item in items:
        row_parts = []
        for col in columns:
            value = str(item.get(col, ""))
            row_parts.append(value.ljust(col_widths[col]))
        output.write(" | ".join(row_parts) + "\n")
    
    resp = Response(output.getvalue(), mimetype="text/plain")
    resp.headers["Content-Disposition"] = f"attachment; filename={kind}.txt"
    return resp

@app.route("/crypto")
@login_required
def crypto():
    buf = io.StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        demo_encryption()
    finally:
        sys.stdout = old
    return render_template("crypto.html", output=buf.getvalue())

@app.route("/billing")
@login_required
def billing():
    """Billing and payment page with QR codes for different payment methods."""
    return render_template("billing.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
