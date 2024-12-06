# This will be logining system
class Register:
    def __init__(self, username, password, email):
        self.username = username
        self.password = password 
        self.email = email
    def __str__(self):
        return f"User(username = {self.username}, email={self.email})"

class UserRegistrationSystem:
    def __init__(self):
        self.users = []

    def is_valid_username(self, username):
        return username
    
    def is_valid_email(self, email):
        return "@" in email

    def check_password(self, pw):
        has_upper = any(char.isupper() for char in pw)
        has_digit = any(char.isdigit() for char in pw)
        has_special = any(char in "!@#$%^&*()_+={}[\\]|\\:;,.<>?" for char in pw)
        
        if len(pw) < 8:
            return "Your Password is Weak."
        if len(pw) >= 8 and not (has_upper and has_digit and has_special):
            return "Your Password is: Moderate"
        if len(pw) >= 8 and has_upper and has_digit and has_special:
            return "Your Password is: Strong"
        
    def register_user(self, username, password, email):
        if not self.is_valid_username(username):
            print("Invalid username.")
            return False
        if not self.is_valid_password(password):
            print("Invalid password.")
            return False
        if not self.is_valid_email(email):
            print("Invalid email address.")
            return False
        
        password_strength = self.check_password(password)
        print(password_strength)
        if "Weak" in password_strength:
            print("Password is too weak. Please choose a stronger password.")
            return False
        
        for user in self.users:
            if user.username == username:
                print("username already taken.")
                return False
        new_user = Register(username, password, email)
        self.users.append(new_user)
        print(f"User {username} registed successfully.")
    def list_users(self):
        if not self.users:
            print("No users registered yet.")
        else:
            print("\n--- Registered Users ---")
            for user in self.users:
                print(user)
if __name__ == "__main__":
    registration_system = UserRegistrationSystem()

    while True:
        print("\n--- User Regsitration ---")
        username = input("Enter username:")
        password = input("Enter password(at least 8 characters):")
        confirm_password = input("Confirm your password:")
        email = input("Enter email (must contain '@'):")

        if registration_system.register_user(username, password, email):
            break

    registration_system.list_users()