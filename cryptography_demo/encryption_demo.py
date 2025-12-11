from cryptography.fernet import Fernet


def demo_encryption():
    print("\n--- CRYPTOGRAPHY DEMO (Encryption) ---")
    key = Fernet.generate_key()
    cipher = Fernet(key)

    message = b"Patient record: John Doe - Blood Type A+"
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)

    print(f"Key (base64): {key.decode()}")
    print(f"Original: {message.decode()}")
    print(f"Encrypted: {encrypted.decode()}")
    print(f"Decrypted: {decrypted.decode()}")
