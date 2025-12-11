import hashlib
import os
import secrets
import time

# Demo in-memory user store with per-user salts and lockout
_USER_DB = {}
_LOCKOUT_STATE = {}
_MAX_ATTEMPTS = 3
_LOCKOUT_SECONDS = 15


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode()).hexdigest()


def _ensure_demo_user():
    username = "admin"
    if username not in _USER_DB:
        salt = secrets.token_bytes(16)
        password = "hospital123"
        _USER_DB[username] = {
            "salt": salt,
            "hash": _hash_password(password, salt),
        }


def login_demo():
    print("\n--- AUTHENTICATION DEMO ---")
    _ensure_demo_user()
    username = input("Enter username: ").strip()

    # Lockout enforcement
    state = _LOCKOUT_STATE.get(username, {"attempts": 0, "until": 0})
    now = time.time()
    if state.get("until", 0) > now:
        remaining = int(state["until"] - now)
        print(f"Account locked. Try again in {remaining}s.")
        return

    password = input("Enter password: ")

    user = _USER_DB.get(username)
    if not user:
        print("❌ Invalid credentials. Access denied.")
        state["attempts"] = state.get("attempts", 0) + 1
        if state["attempts"] >= _MAX_ATTEMPTS:
            state["until"] = now + _LOCKOUT_SECONDS
            state["attempts"] = 0
            print(f"Too many attempts. Locked for {_LOCKOUT_SECONDS}s.")
        _LOCKOUT_STATE[username] = state
        return

    calc = _hash_password(password, user["salt"])
    if secrets.compare_digest(calc, user["hash"]):
        print("✅ Login successful! Access granted.")
        _LOCKOUT_STATE[username] = {"attempts": 0, "until": 0}
    else:
        print("❌ Invalid credentials. Access denied.")
        state["attempts"] = state.get("attempts", 0) + 1
        if state["attempts"] >= _MAX_ATTEMPTS:
            state["until"] = now + _LOCKOUT_SECONDS
            state["attempts"] = 0
            print(f"Too many attempts. Locked for {_LOCKOUT_SECONDS}s.")
        _LOCKOUT_STATE[username] = state
