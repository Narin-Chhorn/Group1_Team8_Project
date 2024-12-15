import hashlib
from datetime import datetime
from cryptography.fernet import Fernet  # type: ignore

USER_DB_FILE = "users.txt"
MAX_ATTEMPTS = 3  # Maximum allowed attempts before locking the account

class Register:
    def __init__(self, username, password_hash, email, dob, encrypted_pin, phone):
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.dob = dob
        self.encrypted_pin = encrypted_pin
        self.phone = phone

class UserRegistrationSystem:
    def __init__(self, file_path="users.txt"):
        self.users = []
        self.file_path = file_path
        # Generate a key for encryption
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def encrypt_pin(self, pin):
        """Encrypt the PIN using the generated key."""
        return self.cipher.encrypt(pin.encode()).decode()

    def decrypt_pin(self, encrypted_pin):
        """Decrypt the PIN using the generated key."""
        return self.cipher.decrypt(encrypted_pin.encode()).decode()

    def is_valid_username(self, username):
        if username.isalpha():
            return username
        return False

    def is_valid_email(self, email):
        if "@" in email and email.endswith("@gmail.com"):
            return True
        return False

    def check_password(self, pw):
        if " " in pw:
            return False
        
        has_upper = any(char.isupper() for char in pw)
        has_digit = any(char.isdigit() for char in pw)
        has_lower = any(char.islower() for char in pw)
        has_special = any(char in "!@#$%^&*()_+={}[\\]|\\:;,.<>?" for char in pw)
        
        if len(pw) < 8:
            return "Your Password should be more than 8 characters."
        if len(pw) >= 8 and not (has_upper and has_lower and has_digit and has_special):
            return "Your Password is Moderate. Consider adding uppercase, digits, and special characters."
        if len(pw) >= 8 and has_upper and has_digit and has_special:
            return "Your Password is Strong."

    def get_dob(self):
        while True:
            dob_input = input("Enter your date of birth (YYYY-MM-DD): ")
            try:
                dob = datetime.strptime(dob_input, "%Y-%m-%d")
                current_date = datetime.now()
                if dob >= current_date:
                    print("The date of birth cannot be in the future. Please enter a valid date.")
                else:
                    return dob_input  # Return as string
            except ValueError:
                print("Invalid date format. Please use YYYY-MM-DD.")
                
    def verify_pin(self):
        while True:
            pin_input = input("Please enter a 4-digit PIN: ")
            if pin_input.isdigit() and len(pin_input) == 4:
                return pin_input
            else:
                print("Invalid input. Please input exactly 4 digits.")

    def validate_phone(self):
        while True:
            phone_input = input("Enter your phone number: ")
            if phone_input.isdigit() and len(phone_input) <= 11 and phone_input[0] == '0' and phone_input[1] != '0':
                return phone_input
            else:
                print("Invalid phone number.")

    def save_users(self):
        """Save users to a file in a clean and readable format."""
        with open(self.file_path, "a") as file:
            for user in self.users:
                # Format each user's data cleanly
                file.write("User Information:\n")
                file.write(f"    Username       : {user.username}\n")
                file.write(f"    Password Hash  : {user.password_hash}\n")
                file.write(f"    Email          : {user.email}\n")
                file.write(f"    Date of Birth  : {user.dob}\n")
                file.write(f"    Encrypted PIN  : {user.encrypted_pin}\n")
                file.write(f"    Phone Number   : {user.phone}\n")
                file.write("-" * 40 + "\n")  # Separator for better readability

    def register_user(self, username, password, confirm_password, email, dob, pin, phone):
        if password != confirm_password:
            print("Passwords do not match. Please Try Again.") 
            return False
        if not self.is_valid_username(username):
            print("Invalid username. Please use only alphabetic characters.")
            return False

        if not self.is_valid_email(email):
            print("Invalid email address. Please enter a valid email ending with @gmail.com.")
            return False
        
        for user in self.users:
            if user.username == username:
                print("Username already taken.")
                return False

        password_hash = self.hash_password(password)
        encrypted_pin = self.encrypt_pin(pin)  # Encrypt the PIN
        new_user = Register(username, password_hash, email, dob, encrypted_pin, phone)
        self.users.append(new_user)
        self.save_users()  # Save user info to the file
        print(f"Registration successful for {new_user.username}.")
        return True

    def list_users(self):
        if not self.users:
            print("No users registered yet.")
        else:
            print("\n--- Registered Users ---")
            for index, user in enumerate(self.users, start=1):
                decrypted_pin = self.decrypt_pin(user.encrypted_pin)  # Decrypt PIN to display
                print(f"{index}. Username: {user.username}, Email: {user.email}, PIN: {decrypted_pin}, Phone: {user.phone}")


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
    with open(USER_DB_FILE, "w") as file:
        for username, data in users.items():
            file.write("User Information:\n")
            file.write(f"    Username       : {username}\n")
            file.write(f"    Password Hash  : {data['password']}\n")
            file.write(f"    Email          : {data.get('email', 'unknown@example.com')}\n")
            file.write(f"    Date of Birth  : {data.get('dob', 'unknown')}\n")
            file.write("    Encrypted PIN  : gAAAAABnWQkEYA44xYbMtL_1eryNvMjKBMn1htngivkVqeRE3jJepuPBheE-ZyQb-iz1gqAggHHd3JHp8FSp0djwUFE8-vyGpg==\n")
            file.write(f"    Phone Number   : {data.get('phone', 'unknown')}\n")
            file.write("----------------------------------------\n")

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

def admin_menu(users):
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
            view_all_users(users)
        elif choice == "2":
            change_user_pin(users)
        elif choice == "3":
            unlock_user_account(users)
        elif choice == "4":
            change_user_dob(users)
        elif choice == "5":
            change_user_email(users)
        elif choice == "0":
            print("Exiting Admin Menu.")
            break
        else:
            print("Invalid choice. Please try again.")


def view_all_users(users):
    print("\n--- All Registered Users ---")
    for username, data in users.items():
        print(f"Username: {username}")
        print(f"Email: {data['email']}")
        print(f"Date of Birth: {data['dob']}")
        print(f"Phone: {data['phone']}")
        print(f"Account Locked: {'Yes' if data['locked'] else 'No'}")
        print("-" * 40)


def change_user_pin(users):
    username = input("Enter the username to change PIN: ").strip()
    if username in users:
        new_pin = input("Enter a new 4-digit PIN: ").strip()
        if new_pin.isdigit() and len(new_pin) == 4:
            cipher = Fernet(UserRegistrationSystem().key)  # Ensure using the same cipher key
            encrypted_pin = cipher.encrypt(new_pin.encode()).decode()
            users[username]["pin"] = encrypted_pin
            print("PIN updated successfully.")
            save_users(users)
        else:
            print("Invalid PIN. Must be exactly 4 digits.")
    else:
        print("Username not found.")


def unlock_user_account(users):
    username = input("Enter the username to unlock: ").strip()
    if username in users:
        users[username]["locked"] = False
        users[username]["attempts"] = 0
        print(f"Account for '{username}' has been unlocked.")
        save_users(users)
    else:
        print("Username not found.")


def change_user_dob(users):
    username = input("Enter the username to change DOB: ").strip()
    if username in users:
        new_dob = input("Enter the new Date of Birth (YYYY-MM-DD): ").strip()
        try:
            # Attempt to parse the provided date
            dob = datetime.strptime(new_dob, "%Y-%m-%d")
            current_date = datetime.now()

            # Check if the DOB is in the future
            if dob > current_date:
                print("The date of birth cannot be in the future. Please enter a valid date.")
            else:
                users[username]["dob"] = new_dob
                print("Date of Birth updated successfully.")
                save_users(users)
        except ValueError:
            print("Invalid date format. Please use YYYY-MM-DD.")
    else:
        print("Username not found.")

def change_user_email(users):
    username = input("Enter the username to change email: ").strip()
    if username in users:
        new_email = input("Enter the new email address: ").strip()
        if "@" in new_email and new_email.endswith("@gmail.com"):
            users[username]["email"] = new_email
            print("Email updated successfully.")
            save_users(users)
        else:
            print("Invalid email. Must be a valid Gmail address.")
    else:
        print("Username not found.")

# Integrate admin menu into the main program
def main():
    registration_system = UserRegistrationSystem()
    users = load_users()

    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Admin Menu")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()

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
            admin_menu(users)

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
