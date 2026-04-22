"""
Secure Text Encryption Program
Author: Andrew Euler
Description:
    A simple command-line program that encrypts and decrypts text using
    password-based encryption. The program uses PBKDF2-HMAC-SHA256 to derive
    a secure key from a password and Fernet for authenticated encryption.

Requirements:
    pip install cryptography
"""

import base64
import json
import os
import getpass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DATA_FILE = "secure_message.json"
PBKDF2_ITERATIONS = 390000


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a secure encryption key from a password using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_text(plaintext: str, password: str) -> dict:
    """
    Encrypt plaintext with a password-derived key.
    Returns a dictionary containing salt, ciphertext, and metadata.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Fernet(key)
    token = cipher.encrypt(plaintext.encode("utf-8"))

    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "ciphertext": token.decode("utf-8"),
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "encryption": "Fernet"
    }


def decrypt_text(encrypted_data: dict, password: str) -> str:
    """
    Decrypt ciphertext with the provided password.
    Raises ValueError if the password is incorrect or the file is invalid.
    """
    try:
        salt = base64.b64decode(encrypted_data["salt"])
        ciphertext = encrypted_data["ciphertext"].encode("utf-8")
        key = derive_key(password, salt)
        cipher = Fernet(key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode("utf-8")
    except (KeyError, InvalidToken, ValueError, TypeError) as exc:
        raise ValueError("Decryption failed. Incorrect password or corrupted file.") from exc


def save_encrypted_file(data: dict, filename: str = DATA_FILE) -> None:
    """
    Save encrypted data to a JSON file.
    """
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def load_encrypted_file(filename: str = DATA_FILE) -> dict:
    """
    Load encrypted data from a JSON file.
    """
    path = Path(filename)
    if not path.exists():
        raise FileNotFoundError(f"No encrypted file found: {filename}")

    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


def create_encrypted_message() -> None:
    """
    Prompt the user for text and a password, then encrypt and save the text.
    """
    print("\n--- Create Encrypted Message ---")
    plaintext = input("Enter the message you want to protect:\n> ").strip()

    if not plaintext:
        print("No message entered. Nothing was saved.")
        return

    password = getpass.getpass("Create a password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match. Operation canceled.")
        return

    if not password:
        print("Password cannot be empty.")
        return

    encrypted_data = encrypt_text(plaintext, password)
    save_encrypted_file(encrypted_data)
    print(f"Message encrypted and saved to '{DATA_FILE}'.")


def open_encrypted_message() -> None:
    """
    Prompt the user for a password and decrypt the saved message.
    """
    print("\n--- Open Encrypted Message ---")
    try:
        encrypted_data = load_encrypted_file()
    except FileNotFoundError as exc:
        print(exc)
        return

    password = getpass.getpass("Enter the password: ")

    try:
        plaintext = decrypt_text(encrypted_data, password)
        print("\nDecrypted Message:")
        print(plaintext)
    except ValueError as exc:
        print(exc)


def main() -> None:
    """
    Main program menu.
    """
    while True:
        print("\nSecure Text Encryption Program")
        print("1. Create encrypted message")
        print("2. Open encrypted message")
        print("3. Exit")

        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            create_encrypted_message()
        elif choice == "2":
            open_encrypted_message()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
