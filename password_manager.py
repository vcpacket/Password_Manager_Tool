# Password Manager Implementation
# Author: VCPacket

# Import necessary libraries
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import json
import getpass
import random
import string

# Step 1: Define the PasswordManager class
class PasswordManager:
    def __init__(self, master_password):
        # Step 2: Initialize the PasswordManager with a master password
        self.master_password = master_password
        self.salt = os.urandom(16)
        self.key = self.derive_key()
        self.passwords = {}

    # Step 3: Derive a key from the master password
    def derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=self.salt,
            length=32
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        return key

    # Step 4: Generate a key for encryption using Fernet
    def generate_key(self):
        return Fernet.generate_key()

    # Step 5: Encrypt data using Fernet
    def encrypt_data(self, data):
        cipher_suite = Fernet(self.key)
        cipher_text = cipher_suite.encrypt(data.encode())
        return cipher_text

    # Step 6: Decrypt data using Fernet
    def decrypt_data(self, cipher_text):
        cipher_suite = Fernet(self.key)
        plain_text = cipher_suite.decrypt(cipher_text).decode()
        return plain_text

    # Step 7: Save a new password
    def save_password(self, website, username, password):
        data = {'username': username, 'password': password}
        encrypted_data = self.encrypt_data(json.dumps(data))
        self.passwords[website] = encrypted_data

    # Step 8: Retrieve a password
    def retrieve_password(self, website):
        if website in self.passwords:
            encrypted_data = self.passwords[website]
            decrypted_data = self.decrypt_data(encrypted_data)
            return json.loads(decrypted_data)
        else:
            return None

    # Step 9: Generate a random password
    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

# Step 10: Define the main function
def main():
    # Step 11: Get the master password from the user
    master_password = getpass.getpass("Enter your master password: ")
    # Step 12: Create an instance of PasswordManager
    password_manager = PasswordManager(master_password)

    while True:
        # Step 13: Display the Password Manager Menu
        print("\nPassword Manager Menu:")
        print("1. Save a new password")
        print("2. Retrieve a password")
        print("3. Generate a password")
        print("4. Quit")

        # Step 14: Get the user's choice
        choice = input("Enter your choice (1-4): ").strip()

        if choice == '1':
            # Step 15: Save a new password
            website = input("Enter the website: ")
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            password_manager.save_password(website, username, password)
            print("Password saved successfully!")

        elif choice == '2':
            # Step 16: Retrieve a password
            website = input("Enter the website: ")
            stored_password = password_manager.retrieve_password(website)
            if stored_password:
                print(f"Username: {stored_password['username']}")
                print(f"Password: {stored_password['password']}")
            else:
                print("Password not found!")

        elif choice == '3':
            # Step 17: Generate a password
            length = int(input("Enter the desired password length: "))
            generated_password = password_manager.generate_password(length)
            print(f"Generated Password: {generated_password}")

        elif choice == '4':
            # Step 18: Quit the program
            break

        else:
            # Step 19: Handle invalid choice
            print("Invalid choice. Please enter a number between 1 and 4.")

# Step 20: Execute the main function if the script is run as the main program
if __name__ == "__main__":
    main()
