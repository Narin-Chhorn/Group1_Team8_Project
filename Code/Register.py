from cryptography.fernet import Fernet # type: ignore
import hashlib
from datetime import datetime

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
        with open("users.txt", "a") as file:
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

if __name__ == "__main__":
    registration_system = UserRegistrationSystem()

    while True:
        print("\n--- User Registration ---")
        
        # Step 1: Enter username
        while True:
            username = input("Enter username:")
            if " " in username:
                print("No spaces allowed in username. Please try again.")
                continue
            if not registration_system.is_valid_username(username):
                print("Invalid username. Only alphabetic characters are allowed.")
                continue
            break

        # Step 2: Enter password
        while True:
            password = input("Enter password:")

            if " " in password:
                print("No space allowed in password. Please try again.")
                continue

            password_strength = registration_system.check_password(password)
            if password_strength == "Your Password is Strong.":
                print(password_strength)
                break
            else:
                print(password_strength)

        # Step 3: Confirm password
        confirm_password = input("Confirm your password:")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue

        # Step 4: Enter email
        while True:
            email = input("Enter email:")
            if " " in email:
                print("No space allowed in email. Please try again.")
                continue
            if not registration_system.is_valid_email(email):
                print("Invalid email address. Please enter a valid email ending with @gmail.com.")
            else:
                break

        # Step 5: Enter date of birth
        dob = registration_system.get_dob()

        # Step 6: Enter 4-digit PIN
        pin = registration_system.verify_pin()

        # Step 7: Enter phone number
        phone = registration_system.validate_phone()

        # Now we proceed to registration
        if registration_system.register_user(username, password, confirm_password, email, dob, pin, phone):
            break

    registration_system.list_users()
