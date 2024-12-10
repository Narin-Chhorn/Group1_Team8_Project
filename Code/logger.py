import hashlib

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class Register:
    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email

    def __str__(self):
        return f"{self.username}, {self.email}"

class UserRegistrationSystem:
    def __init__(self):
        self.users = []

    def is_valid_username(self, username):
        return username.isalnum()  # Checks that username contains only alphanumeric characters

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
            print("Invalid username. It should only contain alphanumeric characters.")
            return False

        password_strength = self.check_password(password)
        print(password_strength)
        if "Your password should be more than 8 characters" in password_strength:
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
        print(f"User registered successfully: {new_user.username}, {new_user.email}")
        return True

    def list_users(self):
        if not self.users:
            print("No users registered yet.")
        else:
            print("Registered Users:")
            for user in self.users:
                print(user)

# User database (in a real-world application, use a secure database)
users = {
    "user1": {
        "password": hash_password("password123"),
        "logs": ["Logged in on 2024-12-01"]
    },
    "Narak": {
        "password": hash_password("@Rak1234"),
        "logs": ["Logged in on 2024-12-8"]
    },
}

# Function for user login
def login():
    while True:
        print("\n1. Login")
        print("0. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            try:
                username = input("Enter your username: ").strip()
                if username in users:
                    password = input("Enter your password: ").strip()
                    if hash_password(password) == users[username]["password"]:
                        print("Login successful!")
                        users[username]["logs"].append("Logged in on 2024-12-09")
                        return username  # Return logged-in username
                    else:
                        print("Incorrect password.")
                else:
                    print("Username not found.")
            except Exception as e:
                print(f"An error occurred during login: {e}")
        elif choice == "0":
            print("Exiting program.")
            exit()
        else:
            print("Invalid choice. Please try again.")

# Function to view logs
def view_logs(username):
    print("\nLogin Logs:")
    for log in users[username]["logs"]:
        print(f"- {log}")

# Function to change password
def change_password(username):
    try:
        new_password = input("Enter your new password: ").strip()
        users[username]["password"] = hash_password(new_password)
        print("Password updated successfully.")
    except Exception as e:
        print(f"An error occurred while changing password: {e}")

# Function to reset password (admin-only feature in real systems)
def reset_password(username):
    print("Resetting password is not allowed for regular users in this demo.")

# Main menu
def menu(username):
    while True:
        try:
            print("\nMenu:")
            print("2. View Logs")
            print("3. Change Password")
            print("4. Reset Password")
            print("0. Exit")

            choice = input("Enter your choice: ").strip()
            if choice == "2":
                view_logs(username)
            elif choice == "3":
                change_password(username)
            elif choice == "4":
                reset_password(username)
            elif choice == "0":
                print("Exiting the program. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

# Main program
def main():
    user_registration_system = UserRegistrationSystem()
    
    print("Welcome to the User Registration System!")
    choice = input("Do you want to register (yes/no)? ").strip().lower()
    
    if choice == "yes":
        username = input("Enter a username: ").strip()
        password = input("Enter a password: ").strip()
        confirm_password = input("Confirm password: ").strip()
        email = input("Enter your email: ").strip()
        
        if user_registration_system.register_user(username, password, confirm_password, email):
            print("Registration successful!")
        else:
            print("Registration failed.")
    else:
        logged_in_user = login()  # Ensure login first
        menu(logged_in_user)      # Show the menu only after successful login

if __name__ == "__main__":
    main()
