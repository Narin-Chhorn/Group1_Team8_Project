import os
import time
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet  # Encryption library
from colorama import init, Fore, Style  # For colored terminal output

# Initialize Colorama for cross-platform support
init(autoreset=True)

# File paths
USER_DB_FILE = "users.txt"
MAX_ATTEMPTS = 3  # Maximum allowed attempts before locking the account

# --- Class for User Registration ---
class Register:
    def __init__(self, username, password_hash, email, dob, encrypted_pin, phone):
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.dob = dob
        self.encrypted_pin = encrypted_pin
        self.phone = phone


# --- User Registration System ---
class UserRegistrationSystem:
    def __init__(self, file_path="users.txt"):
        self.users = []
        self.file_path = file_path
        # Generate a key for encryption
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def hash_password(self, password):
        """Hash a password using SHA256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def encrypt_pin(self, pin):
        """Encrypt the PIN using the generated key."""
        return self.cipher.encrypt(pin.encode()).decode()

    def is_valid_username(self, username):
        """Check if the username contains only alphabets."""
        return username.isalpha()

    def is_valid_email(self, email):
        """Check if the email ends with @gmail.com."""
        return "@" in email and email.endswith("@gmail.com")

    def check_password(self, password):
        """Evaluate the password's strength."""
        has_upper = any(char.isupper() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_special = any(char in "!@#$%^&*()_+={}[\\]|\\:;,.<>?" for char in password)

        if len(password) < 8:
            return "Your password should be more than 8 characters."
        if not (has_upper and has_digit and has_special):
            return "Your password is moderate. Add uppercase, digits, and special characters."
        return "Your password is strong."

    def save_users(self):
        """Save user information to a file."""
        with open(self.file_path, "a") as file:
            for user in self.users:
                file.write("User Information:\n")
                file.write(f"    Username       : {user.username}\n")
                file.write(f"    Password Hash  : {user.password_hash}\n")
                file.write(f"    Email          : {user.email}\n")
                file.write(f"    Date of Birth  : {user.dob}\n")
                file.write(f"    Encrypted PIN  : {user.encrypted_pin}\n")
                file.write(f"    Phone Number   : {user.phone}\n")
                file.write("-" * 40 + "\n")

    def register_user(self):
        """Register a new user."""
        print(Fore.YELLOW + "\n--- User Registration ---")

        # Input validation
        while True:
            username = input(Fore.CYAN + "Enter username: ").strip()
            if not self.is_valid_username(username):
                print(Fore.RED + "Invalid username. Use only alphabetic characters.")
                continue

            password = input(Fore.CYAN + "Enter password: ").strip()
            print(Fore.GREEN + self.check_password(password))
            confirm_password = input(Fore.CYAN + "Confirm password: ").strip()

            if password != confirm_password:
                print(Fore.RED + "Passwords do not match. Please try again.")
                continue

            email = input(Fore.CYAN + "Enter email (must end with @gmail.com): ").strip()
            if not self.is_valid_email(email):
                print(Fore.RED + "Invalid email format. Please try again.")
                continue

            dob = input(Fore.CYAN + "Enter your Date of Birth (YYYY-MM-DD): ").strip()
            pin = input(Fore.CYAN + "Enter a 4-digit PIN: ").strip()
            phone = input(Fore.CYAN + "Enter your phone number: ").strip()

            # Save the user
            password_hash = self.hash_password(password)
            encrypted_pin = self.encrypt_pin(pin)
            new_user = Register(username, password_hash, email, dob, encrypted_pin, phone)
            self.users.append(new_user)
            self.save_users()
            print(Fore.GREEN + f"Registration successful! Welcome, {username}.")
            break


# --- User Login System ---
def login(users):
    """Handle user login."""
    print(Fore.YELLOW + "\n--- User Login ---")
    username = input(Fore.CYAN + "Enter username: ").strip()

    if username in users:
        attempts = 0
        while attempts < MAX_ATTEMPTS:
            password = input(Fore.CYAN + "Enter your password: ").strip()
            if users[username]["password"] == hashlib.sha256(password.encode()).hexdigest():
                print(Fore.GREEN + "Login successful!")
                return username
            else:
                attempts += 1
                print(Fore.RED + f"Incorrect password. {MAX_ATTEMPTS - attempts} attempts left.")

        print(Fore.RED + "Account locked due to too many failed login attempts.")
    else:
        print(Fore.RED + "Username not found.")


# --- Main Menu ---
def main():
    system = UserRegistrationSystem()
    users = {}  # Placeholder for users data

    while True:
        # Display the main menu
        print(Fore.BLUE + Style.BRIGHT + "\n=== SecureGate Authentication System ===")
        print(Fore.GREEN + "1. Register")
        print(Fore.YELLOW + "2. Login")
        print(Fore.RED + "3. Exit")

        choice = input(Fore.CYAN + "Enter your choice: ").strip()

        if choice == "1":
            system.register_user()

        elif choice == "2":
            login(users)

        elif choice == "3":
            print(Fore.GREEN + "Exiting SecureGate. Goodbye!")
            time.sleep(1)
            break

        else:
            print(Fore.RED + "Invalid choice. Please try again.")


# Run the program
if __name__ == "__main__":
    main()
