import hashlib

class Register:
    def __init__(self, username, password, email):
        self.username = username
        self.hashed_password = Register.hash_password(password)
        self.email = email

    @staticmethod
    def hash_password(password):
        """Hash a password using SHA256."""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def verify_password(stored_hash, password):
        """Verify a hashed password."""
        return stored_hash == hashlib.sha256(password.encode()).hexdigest()

    def __str__(self):
        return f"{self.username}, {self.email}"


class UserRegistrationSystem:
    def __init__(self):
        self.users = []

    def is_valid_username(self, username):
        return len(username) > 0

    def is_valid_email(self, email):
        return "@" in email

    def check_password(self, pw):
        has_upper = any(char.isupper() for char in pw)
        has_digit = any(char.isdigit() for char in pw)
        has_special = any(char in "!@#$%^&*()_+={}[\\]|\\:;,.<>?" for char in pw)

        if len(pw) < 8:
            return "Your Password should be more than 8 characters."
        if len(pw) >= 8 and not (has_upper and has_digit and has_special):
            return "Your Password is Moderate. Consider adding uppercase, digits, and special characters."
        if len(pw) >= 8 and has_upper and has_digit and has_special:
            return "Your Password is Strong."

    def register_user(self, username, password, confirm_password, email):
        if password != confirm_password:
            print("Passwords do not match. Please Try Again.")
            return False
        if not self.is_valid_username(username):
            print("Invalid username.")
            return False

        password_strength = self.check_password(password)
        print(password_strength)
        if "Your Password should be more than 8 characters" in password_strength:
            print("Password is too weak. Please choose a stronger password.")
            return False
        if "Moderate" in password_strength:
            print("Password is moderate. Consider improving your password for better security.")
        if not self.is_valid_email(email):
            print("Invalid email address.")
            return False

        for user in self.users:
            if user.username == username:
                print("Username already taken.")
                return False

        new_user = Register(username, password, email)
        self.users.append(new_user)
        print(f"User Registered: {new_user.username}, {new_user.email}")
        return True

    def list_users(self):
        if not self.users:
            print("No users registered yet.")
        else:
            print("\n--- Registered Users ---")
            for index, user in enumerate(self.users, start=1):
                print(f"{index}. {user} (Hashed Password: {user.hashed_password})")


if __name__ == "__main__":
    registration_system = UserRegistrationSystem()

    while True:
        print("\n--- User Registration ---")
        username = input("Enter username: ")
        while True:
            password = input("Enter password: ")
            password_strength = registration_system.check_password(password)
            print(password_strength)
            if "Your Password should be more than 8 characters" in password_strength:
                print("Password is too weak. Please choose a stronger password.")
            elif "Moderate" in password_strength:
                print("Password is moderate. Consider improving your password for better security.")
            else:
                break
        confirm_password = input("Confirm your password: ")
        email = input("Enter email (must contain '@'): ")

        if registration_system.register_user(username, password, confirm_password, email):
            break

    registration_system.list_users()
