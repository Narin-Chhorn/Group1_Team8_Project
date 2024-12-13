# This will be the place for Admin Code
import hashlib
import os
import re
import ast

# Admin Class
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


# Admin Management System
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
                    admin_dict = ast.literal_eval(line.strip())
                    admins.append(Admin(admin_dict["username"], admin_dict["hashed_password"]))
        except FileNotFoundError:
            # Create a default admin account if no admin file exists
            default_admin = Admin("admin", Admin.hash_password("Admin123!!"))
            admins.append(default_admin)
            self.save_admins(admins)
        return admins

    def load_users(self):
        """Load users from a human-readable file."""
        users = []
        try:
            with open(self.user_file, "r") as file:
                content = file.read()
                user_blocks = content.split("----------------------------------------")
                for block in user_blocks:
                    if "User Information:" not in block.strip():
                        continue
                    user_data = {}
                    for line in block.strip().split("\n"):
                        if ":" in line:
                            key, value = map(str.strip, line.split(":", 1))
                            user_data[key] = value
                    
                    # Check if all necessary keys are in the user data, if not, skip
                    required_keys = ["username", "email", "dob", "phone"]
                    if all(key in user_data for key in required_keys):
                        users.append(user_data)
                    else:
                        print(f"Skipping invalid user entry: {user_data}")

        except FileNotFoundError:
            print(f"File {self.user_file} not found. No users loaded.")
        except ValueError as ve:
            print(f"Error parsing user data: {ve}")

        return users


    def save_admins(self, admins):
        """Save admin accounts to a file."""
        with open(self.admin_file, "w") as file:
            for admin in admins:
                admin_dict = {"username": admin.username, "hashed_password": admin.hashed_password}
                file.write(str(admin_dict) + "\n")

    def save_users(self):
        """Save users to a human-readable file."""
        with open(self.user_file, "w") as file:
            for user in self.users:
                file.write("User Information:\n")
                file.write(f"    Username       : {user['username']}\n")
                file.write(f"    Password Hash  : {user['hashed_password']}\n")
                file.write(f"    Email          : {user['email']}\n")
                file.write(f"    Date of Birth  : {user['dob']}\n")
                file.write(f"    Encrypted PIN  : {user.get('Encrypted PIN', 'N/A')}\n")
                file.write(f"    Phone Number   : {user['phone']}\n")
                file.write("----------------------------------------\n")

    def find_admin(self, username):
        """Find an admin by username."""
        return next((admin for admin in self.admins if admin.username == username), None)

    def find_user(self, username):
        """Find a user by username."""
        return next((user for user in self.users if user["username"] == username), None)

    def admin_login(self):
        """Admin login."""
        print("\n--- Admin Login ---")
        username = input("Enter admin username: ")
        admin = self.find_admin(username)

        if not admin:
            print("Admin username not found.")
            return

        password = input("Enter admin password: ")

        if Admin.verify_password(admin.hashed_password, password):
            print("Admin login successful!")
            self.admin_menu()
        else:
            print("Incorrect password.")

    def admin_menu(self):
        """Admin menu options."""
        while True:
            print("\n--- Admin Menu ---")
            print("1. View Users Info")
            print("2. Update User Info")
            print("3. Unlock User Account")
            print("4. Logout")
            choice = input("Choose an option: ")

            if choice == "1":
                self.view_users()
            elif choice == "2":
                self.update_user()
            elif choice == "3":
                self.unlock_user_account()
            elif choice == "4":
                print("Logging out as admin...")
                break
            else:
                print("Invalid choice. Please try again.")

    def admin_menu(self):
        """Admin menu options."""
        while True:
            print("\n--- Admin Menu ---")
            print("1. View Users Info")
            print("2. Update User Info")
            print("3. Unlock User Account")
            print("4. Logout")
            choice = input("Choose an option: ")

            if choice == "1":
                self.view_users()
            elif choice == "2":
                self.update_user()
            elif choice == "3":
                self.unlock_user_account()
            elif choice == "4":
                print("Logging out as admin...")
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
            # Debugging: Print the user dictionary to inspect its structure
            print(f"Debugging: {user}")
            try:
                print(f"User {idx}:")
                print(f"    Username       : {user['username']}")
                print(f"    Email          : {user['email']}")
                print(f"    Date of Birth  : {user['dob']}")
                print(f"    Phone Number   : {user['phone']}")
                print(f"    Locked         : {'Yes' if user.get('locked', False) else 'No'}")
                print("----------------------------------------")
            except KeyError as e:
                print(f"KeyError: Missing {e} in user data.")


    def update_user(self):
        """Update user information."""
        username = input("Enter the username of the user to update: ")
        user = self.find_user(username)

        if user:
            print("What would you like to update?")
            print("1. Username")
            print("2. Email")
            print("3. Phone Number")
            choice = input("Choose an option: ")

            if choice == "1":
                new_username = input("Enter the new username: ")
                if self.is_valid_username(new_username):
                    user["username"] = new_username
                    print("Username updated successfully.")
                else:
                    print("Username is either invalid or already taken.")
            elif choice == "2":
                new_email = input("Enter the new email: ")
                if self.is_valid_email(new_email):
                    user["email"] = new_email
                    print("Email updated successfully.")
                else:
                    print("Invalid email format.")
            elif choice == "3":
                new_phone = input("Enter the new phone number: ")
                if self.is_valid_phone_number(new_phone):
                    user["phone"] = new_phone
                    print("Phone number updated successfully.")
                else:
                    print("Invalid phone number format.")
            else:
                print("Invalid choice.")

            self.save_users()
        else:
            print("User not found.")

    def unlock_user_account(self):
        """Unlock a locked user account."""
        username = input("Enter the username to unlock: ")
        user = self.find_user(username)

        if user:
            # Assuming 'locked' is now a boolean value (True or False)
            if user.get("locked", False):  # Check if user is locked (boolean comparison)
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

    # Helper Methods for Validation

    def is_valid_username(self, username):
        """Validate username uniqueness and format."""
        if username.isalnum() and len(username) >= 3 and all(user["username"] != username for user in self.users):
            return True
        return False

    def is_valid_email(self, email):
        """Validate email format."""
        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        return re.match(email_regex, email) is not None

    def is_valid_phone_number(self, phone):
        """Validate phone number format."""
        phone_regex = r"^\+?[1-9]\d{1,14}$"  # Simple regex for international phone numbers
        return re.match(phone_regex, phone) is not None


def main():
    system = AdminManagementSystem()

    while True:
        print("\n--- Main Menu ---")
        print("1. Admin Login")
        print("2. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            system.admin_login()
        elif choice == "2":
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
