import hashlib
import ast
import os
import re
from datetime import datetime
from cryptography.fernet import Fernet  # type: ignore
from colorama import init, Fore, Style  # For colored terminal output

# Initialize Colorama for cross-platform terminal color support
init(autoreset=True)

USER_DB_FILE = "users.txt"

# Constants
MAX_ATTEMPTS = 3  # Maximum allowed attempts before locking the account


# ---------- Register Class ----------
class Register:
    def __init__(self, username, password_hash, email, dob, encrypted_pin, phone):
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.dob = dob
        self.encrypted_pin = encrypted_pin
        self.phone = phone


# ---------- Admin Class ----------
class Admin:
    def __init__(self, username, hashed_password):
        self.username = username
        self.hashed_password = hashed_password

    @staticmethod
    def hash_password(password):
        """Hash a password using SHA256."""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def verify_password(stored_hash, password):
        """Verify a hashed password."""
        return stored_hash == hashlib.sha256(password.encode()).hexdigest()


# ---------- User Registration System ----------
class UserRegistrationSystem:
    def __init__(self, file_path=USER_DB_FILE):
        self.users = []  # List to store user objects
        self.file_path = file_path
        # Generate a key for encryption
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def hash_password(self, password):
        """Hash the password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def encrypt_pin(self, pin):
        """Encrypt the PIN using the generated key."""
        try:
            return self.cipher.encrypt(pin.encode()).decode()
        except Exception as e:
            print(Fore.RED + f"Error encrypting PIN: {e}")

    def decrypt_pin(self, encrypted_pin):
        """Decrypt the PIN using the generated key."""
        try:
            return self.cipher.decrypt(encrypted_pin.encode()).decode()
        except Exception as e:
            print(Fore.RED + f"Error decrypting PIN: {e}")

    def is_valid_username(self, username):
        """Validate username: only alphabetic characters allowed."""
        return username.isalpha()

    def is_valid_email(self, email):
        """Validate email format."""
        return re.match(r"^[\w\.-]+@gmail\.com$", email)

    def check_password(self, pw):
        """Check password strength."""
        if " " in pw:
            return "Password cannot contain spaces."

        has_upper = any(char.isupper() for char in pw)
        has_digit = any(char.isdigit() for char in pw)
        has_special = any(char in "!@#$%^&*()_+={}[\\]|\\:;,.<>?" for char in pw)

        if len(pw) < 8:
            return "Your Password should be more than 8 characters."
        if not (has_upper and has_digit and has_special):
            return "Your Password is Moderate. Add uppercase, digits, and special characters."
        return "Your Password is Strong."

    def get_dob(self):
        """Get a valid date of birth from user."""
        while True:
            try:
                dob_input = input("Enter your date of birth (YYYY-MM-DD): ").strip()
                dob = datetime.strptime(dob_input, "%Y-%m-%d")
                if dob >= datetime.now():
                    raise ValueError("Date of birth cannot be in the future.")
                return dob_input
            except ValueError as e:
                print(Fore.RED + f"Invalid date: {e}")

    def verify_pin(self):
        """Verify the PIN: exactly 4 digits."""
        while True:
            pin_input = input("Enter a 4-digit PIN: ").strip()
            if pin_input.isdigit() and len(pin_input) == 4:
                return pin_input
            else:
                print(Fore.RED + "PIN must be exactly 4 digits.")

    def validate_phone(self):
        """Validate phone number format."""
        while True:
            phone_input = input("Enter your phone number: ").strip()
            if phone_input.isdigit() and len(phone_input) <= 11 and phone_input[0] == '0' and phone_input[1] != '0':
                return phone_input
            else:
                print(Fore.RED + "Invalid phone number format. Try again.")

    def save_users(self):
        """Save users to a file in a readable format."""
        try:
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
        except Exception as e:
            print(Fore.RED + f"Error saving users: {e}")

    def register_user(self):
        """Handles user registration with validations."""
        print(Fore.YELLOW + "\n--- User Registration ---")
        while True:
            try:
                username = input("Enter a username (alphabetic only): ").strip()
                if not self.is_valid_username(username):
                    raise ValueError("Username must contain only alphabetic characters.")

                email = input("Enter email (@gmail.com): ").strip()
                if not self.is_valid_email(email):
                    raise ValueError("Invalid email format. Use '@gmail.com'.")

                while True:
                    password = input("Enter password: ").strip()
                    password_feedback = self.check_password(password)
                    print(Fore.GREEN + password_feedback)
                    if password_feedback == "Your Password is Strong.":
                        break

                confirm_password = input("Confirm your password: ").strip()
                if password != confirm_password:
                    raise ValueError("Passwords do not match.")

                dob = self.get_dob()
                pin = self.verify_pin()
                phone = self.validate_phone()

                password_hash = self.hash_password(password)
                encrypted_pin = self.encrypt_pin(pin)

                new_user = Register(username, password_hash, email, dob, encrypted_pin, phone)
                self.users.append(new_user)
                self.save_users()

                print(Fore.GREEN + f"Registration successful! Welcome, {username}.")
                break
            except Exception as e:
                print(Fore.RED + f"Error: {e}. Please try again.")

    def register_user(self, username, password, confirm_password, email, dob, pin, phone):
        """
        Handles user registration with validations and error handling.
        """
        try:
            # Check for password confirmation
            if password != confirm_password:
                raise ValueError("Passwords do not match. Please try again.")
            
            # Validate username
            if not self.is_valid_username(username):
                raise ValueError("Invalid username. Please use only alphabetic characters.")
            
            # Validate email
            if not self.is_valid_email(email):
                raise ValueError("Invalid email address. Please enter a valid email ending with @gmail.com.")

            # Check for existing username
            for user in self.users:
                if user.username == username:
                    raise ValueError("Username already taken. Please choose another one.")

            # Hash the password and encrypt the PIN
            try:
                password_hash = self.hash_password(password)
                encrypted_pin = self.encrypt_pin(pin)  # Encrypt PIN securely
            except Exception as e:
                raise Exception(f"Encryption error: {e}")

            # Create and save the new user
            new_user = Register(username, password_hash, email, dob, encrypted_pin, phone)
            self.users.append(new_user)
            self.save_users()
            print(f"Registration successful for {new_user.username}.")
            return True

        except ValueError as ve:
            print(Fore.RED + f"Error: {ve}")
            return False
        except Exception as e:
            print(Fore.RED + f"Unexpected error: {e}")
            return False


    def list_users(self):
        """
        Display all registered users with decrypted PINs. Adds error handling.
        """
        try:
            if not self.users:
                print("No users registered yet.")
            else:
                print("\n--- Registered Users ---")
                for index, user in enumerate(self.users, start=1):
                    try:
                        decrypted_pin = self.decrypt_pin(user.encrypted_pin)  # Decrypt PIN securely
                        print(f"{index}. Username: {user.username}, Email: {user.email}, PIN: {decrypted_pin}, Phone: {user.phone}")
                    except Exception as e:
                        print(Fore.RED + f"Error decrypting PIN for user '{user.username}': {e}")
        except Exception as e:
            print(Fore.RED + f"An error occurred while listing users: {e}")


# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to load user data from the human-readable format
def load_users():
    users = {}
    try:
        with open(USER_DB_FILE, "r") as file:
            user_blocks = file.read().strip().split("----------------------------------------")
            for block in user_blocks:
                lines = block.strip().split("\n")
                if not lines or len(lines) < 6:  # Skip incomplete user blocks
                    continue
                username = lines[1].split(":")[-1].strip()
                hashed_password = lines[2].split(":")[-1].strip()
                email = lines[3].split(":")[-1].strip()
                dob = lines[4].split(":")[-1].strip()
                phone = lines[6].split(":")[-1].strip()
                users[username] = {
                    "password": hashed_password,
                    "email": email,
                    "dob": dob,
                    "phone": phone,
                    "logs": [],  # No logs in this format
                    "attempts": 0,  # Default to 0
                    "locked": False,  # Default to False
                }
    except FileNotFoundError:
        print(f"File '{USER_DB_FILE}' not found. No users loaded.")
    return users

# Function to save user data in the human-readable format
def save_users(users):
    """
    Save user information to a file in a structured format.
    Adds error handling for file operations and data consistency.
    
    Args:
        users (dict): A dictionary of users, where the key is the username 
                      and the value is a dictionary of user data.
    """
    try:
        # Ensure the file directory exists
        directory = os.path.dirname(USER_DB_FILE)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

        # Open the file safely and write user data
        with open(USER_DB_FILE, "w") as file:
            for username, data in users.items():
                if not isinstance(data, dict):  # Ensure data consistency
                    print(f"Skipping invalid data for user '{username}'")
                    continue

                # Write user data to file
                try:
                    file.write("User Information:\n")
                    file.write(f"    Username       : {username}\n")
                    file.write(f"    Password Hash  : {data.get('password', 'N/A')}\n")
                    file.write(f"    Email          : {data.get('email', 'unknown@example.com')}\n")
                    file.write(f"    Date of Birth  : {data.get('dob', 'unknown')}\n")
                    file.write("    Encrypted PIN  : gAAAAABnWQkEYA44xYbMtL_1eryNvMjKBMn1htngivkVqeRE3jJepuPBheE-ZyQb-iz1gqAggHHd3JHp8FSp0djwUFE8-vyGpg==\n")
                    file.write(f"    Phone Number   : {data.get('phone', 'unknown')}\n")
                    file.write("----------------------------------------\n")
                except KeyError as ke:
                    print(f"Missing key '{ke}' in user data for '{username}'. Skipping this user.")
                except Exception as e:
                    print(f"Unexpected error while writing data for '{username}': {e}")

        print("User data saved successfully.")
    
    except PermissionError:
        print("Error: Permission denied. Cannot save user data to the file.")
    except FileNotFoundError:
        print("Error: File path not found. Please check the USER_DB_FILE path.")
    except Exception as e:
        print(f"An unexpected error occurred while saving users: {e}")

# Function for user login
def login(users):
    username = input("Enter your username: ").strip()

    if username in users:
        user = users[username]

        if user["locked"]:
            print("Your account is locked due to too many failed login attempts. Please try again later.")
            return None

        password = input("Enter your password: ").strip()
        if hash_password(password) == user["password"]:
            print("Login successful!")
            # Add login log with timestamp
            user["logs"].append(f"Logged in on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            user["attempts"] = 0  # Reset attempts on successful login
            save_users(users)  # Save updated logs and reset attempts
            return username  # Return logged-in username
        else:
            user["attempts"] += 1
            if user["attempts"] >= MAX_ATTEMPTS:
                user["locked"] = True
                print(f"Account locked due to {MAX_ATTEMPTS} failed attempts.")
            else:
                print(f"Incorrect password. You have {MAX_ATTEMPTS - user['attempts']} attempt(s) left.")
            save_users(users)  # Save updated attempts and lock status
    else:
        print("Username not found.")


# Function to view all user information
def view_info(users, username):
    user_data = users.get(username)
    if user_data:
        print(f"\nUser Information for '{username}':")
        print(f"Username: {username}")
        print(f"Email: {user_data['email']}")
        print(f"Date of Birth: {user_data['dob']}")
        print(f"Phone: {user_data['phone']}")
        print("Login Logs:")
        for log in user_data["logs"]:
            print(f"- {log}")
    else:
        print(f"No information found for user '{username}'.")


# Main menu for post-login actions
def menu(users, username):
    while True:
        try:
            print("\nMenu:")
            print("1. View Info")  # New option for viewing all info
            print("2. Change Password")
            print("0. Exit")

            choice = input("Enter your choice: ").strip()
            if choice == "1":
                view_info(users, username)  # Call the new function
            elif choice == "2":
                change_password(users, username)
            elif choice == "0":
                print("Exiting the program. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

# Function to change password
def change_password(users, username):
    curr_password = input("Enter your current password: ")
    # Hash the entered current password to compare with stored hashed password
    if hash_password(curr_password) == users[username]["password"]:
        try:
            new_password = input("Enter your new password: ").strip()
            users[username]["password"] = hash_password(new_password)
            print("Password updated successfully.")
            save_users(users)  # Save changes to file
        except Exception as e:
            print(f"An error occurred while changing password: {e}")

class AdminManagementSystem:
    def __init__(self, admin_file="admins.txt", user_file="users.txt"):
        self.admin_file = admin_file
        self.user_file = user_file
        self.admins = self.load_admins()
        self.users = self.load_users()

    def load_admins(self):
        """Load admin accounts from a file."""
        admins = []
        try:
            with open(self.admin_file, "r") as file:
                for line in file:
                    try:
                        admin_dict = ast.literal_eval(line.strip())
                        admins.append(Admin(admin_dict["username"], admin_dict["hashed_password"]))
                    except (ValueError, SyntaxError):
                        print(f"Skipping malformed line: {line.strip()}")
        except FileNotFoundError:
            default_admin = Admin("admin", Admin.hash_password("Admin123!!"))
            admins.append(default_admin)
            self.save_admins(admins)
        return admins

    def load_users(self):
        """Load user data from the file into a structured list."""
        users = []
        try:
            with open(self.user_file, 'r') as file:
                user_data = {}
                for line in file:
                    line = line.strip()
                    if line.startswith("Username"):
                        user_data['username'] = line.split(':', 1)[1].strip()
                    elif line.startswith("Password Hash"):
                        user_data['password_hash'] = line.split(':', 1)[1].strip()
                    elif line.startswith("Email"):
                        user_data['email'] = line.split(':', 1)[1].strip()
                    elif line.startswith("Date of Birth"):
                        user_data['dob'] = line.split(':', 1)[1].strip()
                    elif line.startswith("Encrypted PIN"):
                        user_data['encrypted_pin'] = line.split(':', 1)[1].strip()
                    elif line.startswith("Phone Number"):
                        user_data['phone'] = line.split(':', 1)[1].strip()
                    elif line.startswith("----------------------------------------"):
                        users.append(user_data)
                        user_data = {}
        except FileNotFoundError:
            print(f"Error: File '{self.user_file}' not found.")
        return users

    def save_admins(self, admins):
        """Save admin accounts to a file."""
        with open(self.admin_file, "w") as file:
            for admin in admins:
                admin_dict = {"username": admin.username, "hashed_password": admin.hashed_password}
                file.write(str(admin_dict) + "\n")

    def save_users(self):
        """Save users to a human-readable file."""
        try:
            with open(self.user_file, "w") as file:
                for user in self.users:
                    file.write("User Information:\n")
                    file.write(f"    Username       : {user.get('username', 'N/A')}\n")
                    file.write(f"    Password Hash  : {user.get('password_hash', 'N/A')}\n")
                    file.write(f"    Email          : {user.get('email', 'N/A')}\n")
                    file.write(f"    Date of Birth  : {user.get('dob', 'N/A')}\n")
                    file.write(f"    Encrypted PIN  : {user.get('encrypted_pin', 'N/A')}\n")
                    file.write(f"    Phone Number   : {user.get('phone', 'N/A')}\n")
                    file.write(f"    Locked         : {'Yes' if user.get('locked') else 'No'}\n")
                    file.write("----------------------------------------\n")
        except Exception as e:
            print(f"Error saving user data: {e}")

    def find_admin(self, username):
        """Find an admin by username."""
        return next((admin for admin in self.admins if admin.username == username), None)

    def find_user(self, username):
        """Find a user by username."""
        return next((user for user in self.users if user["username"] == username), None)

    def admin_login(self):
        """Admin login."""
        print("\n--- Admin Login ---")
        username = input("Enter admin username: ").strip()
        admin = self.find_admin(username)

        if not admin:
            print("Admin username not found.")
            return False

        password = input("Enter admin password: ").strip()

        if Admin.verify_password(admin.hashed_password, password):
            print("Admin login successful!")
            return True
        else:
            print("Incorrect password.")
            return False

    def admin_menu(self):
        while True:
            print("\n--- Admin Menu ---")
            print("1. View All User Information")
            print("2. Change User PIN")
            print("3. Unlock User Account")
            print("4. Change User Date of Birth")
            print("5. Change User Email")
            print("0. Exit")
            
            choice = input("Enter your choice: ").strip()
            
            if choice == "1":
                self.view_users()
            elif choice == "2":
                self.change_user_pin()
            elif choice == "3":
                self.unlock_user_account()
            elif choice == "4":
                self.change_user_dob()
            elif choice == "5":
                self.change_user_email()
            elif choice == "0":
                print("Exiting Admin Menu.")
                break
            else:
                print("Invalid choice. Please try again.")


    def view_users(self):
        """View all users with detailed information."""
        print("\n--- User Info ---")
        if not self.users:
            print("No users found.")
            return

        for idx, user in enumerate(self.users, start=1):
            print(f"User {idx}:")
            print(f"    Username       : {user.get('username', 'N/A')}")
            print(f"    Password Hash  : {user.get('password_hash', 'N/A')}")
            print(f"    Email          : {user.get('email', 'N/A')}")
            print(f"    Date of Birth  : {user.get('dob', 'N/A')}")
            print(f"    Encrypted PIN  : {user.get('encrypted_pin', 'N/A')}")
            print(f"    Phone Number   : {user.get('phone', 'N/A')}")
            print(f"    Locked         : {'Yes' if user.get('locked') else 'No'}")
            print("----------------------------------------")


    def change_user_pin(self):
        """Change a user's PIN."""
        username = input("Enter the username to change the PIN: ")
        user = self.find_user(username)

        if user:
            new_pin = input("Enter a new 4-digit PIN: ")
            if len(new_pin) == 4 and new_pin.isdigit():
                user['encrypted_pin'] = new_pin  # Update the PIN (encrypt if needed)
                self.save_users()
                print(f"PIN for user '{username}' has been successfully updated.")
            else:
                print("Invalid PIN. It must be exactly 4 digits.")
        else:
            print("User not found.")



    def unlock_user_account(self):
        """Unlock a locked user account."""
        username = input("Enter the username to unlock: ")
        user = self.find_user(username)

        if user:
            if user.get("locked", False):
                confirm = input(f"Are you sure you want to unlock user '{username}'? (y/n): ")
                if confirm.lower() == 'y':
                    user["locked"] = False
                    print(f"User '{username}' has been unlocked.")
                    self.save_users()
                else:
                    print("Unlock operation cancelled.")
            else:
                print(f"User '{username}' is not locked.")
        else:
            print("User not found.")


    def change_user_dob(self):
        """Change a user's Date of Birth."""
        username = input("Enter the username to change the DOB: ")
        user = self.find_user(username)

        if user:
            new_dob = input("Enter new Date of Birth (YYYY-MM-DD): ")
            try:
                datetime.strptime(new_dob, "%Y-%m-%d")
                user['dob'] = new_dob
                self.save_users()
                print(f"Date of Birth for user '{username}' has been successfully updated.")
            except ValueError:
                print("Invalid date format. It must be YYYY-MM-DD.")
        else:
            print("User not found.")


    def change_user_email(self):
        """Change a user's Email."""
        username = input("Enter the username to change the email: ")
        user = self.find_user(username)

        if user:
            new_email = input("Enter the new email address: ")
            if re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", new_email):
                user['email'] = new_email
                self.save_users()
                print(f"Email for user '{username}' has been successfully updated.")
            else:
                print("Invalid email format.")
        else:
            print("User not found.")

# Integrate admin menu into the main program
def main():
    registration_system = UserRegistrationSystem()
    users = load_users()
    system = AdminManagementSystem()

    while True:
        print(Fore.YELLOW + Style.BRIGHT + "=" * 50)
        print(Fore.YELLOW + Style.BRIGHT + "        Welcome to SecureGate v1.0")
        print(Fore.YELLOW + Style.BRIGHT + "   Your Secure Authentication System 🚀")
        print(Fore.YELLOW + Style.BRIGHT + "=" * 50 + "\n")

        print(Fore.BLUE + "====Main Menu====")
        print(Fore.WHITE +"1. Register")
        print(Fore.WHITE +"2. Login")
        print(Fore.WHITE +"3. Admin Menu")
        print(Fore.WHITE +"0. Exit")
        choice = input( Fore.WHITE + "Enter your choice: ").strip()

        if choice == "1":
            while True:
                print("\n--- User Registration ---")
                
                username = input("Enter username: ")
                if " " in username or not registration_system.is_valid_username(username):
                    print("Invalid username. Please try again.")
                    continue

                password = input("Enter password: ")
                password_strength = registration_system.check_password(password)
                if password_strength != "Your Password is Strong.":
                    print(password_strength)
                    continue

                confirm_password = input("Confirm your password: ")
                if password != confirm_password:
                    print("Passwords do not match. Please try again.")
                    continue

                email = input("Enter email: ")
                if not registration_system.is_valid_email(email):
                    print("Invalid email address. Must end with @gmail.com.")
                    continue

                dob = registration_system.get_dob()
                pin = registration_system.verify_pin()
                phone = registration_system.validate_phone()

                if registration_system.register_user(username, password, confirm_password, email, dob, pin, phone):
                    break
 
        elif choice == "2":
            logged_in_user = login(users)
            if logged_in_user:
                menu(users, logged_in_user)

        elif choice == "3":
            if system.admin_login():
                system.admin_menu()
            else:
                print("Login as Admin fail.")

        elif choice == "0":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
