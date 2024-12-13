import hashlib
from datetime import datetime

USER_DB_FILE = "users.txt"
MAX_ATTEMPTS = 3  # Maximum allowed attempts before locking the account

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
            # Adding a placeholder for Encrypted PIN
            file.write("    Encrypted PIN  : gAAAAABnWQkEYA44xYbMtL_1eryNvMjKBMn1htngivkVqeRE3jJepuPBheE-ZyQb-iz1gqAggHHd3JHp8FSp0djwUFE8-vyGpg==\n")
            file.write(f"    Phone Number   : {data.get('phone', 'unknown')}\n")
            file.write("----------------------------------------\n")

# Function for user login
def login(users):
    while True:
        print("\n1. Login")
        print("0. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
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
        elif choice == "0":
            print("Exiting program.")
            exit()
        else:
            print("Invalid choice. Please try again.")

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

# Function to reset password (optional feature)
def reset_password(users, username):
    print("Resetting password is not allowed for regular users in this demo.")

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

# Main menu
def menu(users, username):
    while True:
        try:
            print("\nMenu:")
            print("1. View Info")  # New option for viewing all info
            print("2. Change Password")
            print("3. Reset Password")
            print("0. Exit")

            choice = input("Enter your choice: ").strip()
            if choice == "1":
                view_info(users, username)  # Call the new function
            elif choice == "2":
                change_password(users, username)
            elif choice == "3":
                reset_password(users, username)
            elif choice == "0":
                print("Exiting the program. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

# Main program
if __name__ == "__main__":
    users = load_users()  # Load users from `users.txt`
    logged_in_user = login(users)  # Ensure login first
    if logged_in_user:
        menu(users, logged_in_user)  # Show the menu only after successful login
