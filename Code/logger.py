import hashlib
import ast  # For safely parsing stringified dictionaries

USER_DB_FILE = "users.txt"

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to load user data from `users.txt`
def load_users():
    users = {}
    try:
        with open(USER_DB_FILE, "r") as file:
            for line in file:
                user_data = ast.literal_eval(line.strip())  # Convert string to dictionary
                username = user_data["username"]
                users[username] = {
                    "password": user_data["hashed_password"],
                    "logs": user_data.get("logs", [])  # Defaults to an empty list if no logs
                }
    except FileNotFoundError:
        print(f"File '{USER_DB_FILE}' not found. No users loaded.")
    return users

# Function to save user data back to `users.txt`
# Function to save user data back to `users.txt`
def save_users(users):
    with open(USER_DB_FILE, "w") as file:
        for username, data in users.items():
            user_dict = {
                "username": username,
                "hashed_password": data["password"],
                "email": data.get("email", "unknown@example.com"),  # Default email if missing
                "logs": data["logs"]
            }
            file.write(str(user_dict) + "\n")

# Function for user login
def login(users):
    while True:
        print("\n1. Login")
        print("0. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            username = input("Enter your username: ").strip()
            if username in users:
                password = input("Enter your password: ").strip()
                if hash_password(password) == users[username]["password"]:
                    print("Login successful!")
                    users[username]["logs"].append("Logged in on 2024-12-09")
                    save_users(users)  # Save updated logs
                    return username  # Return logged-in username
                else:
                    print("Incorrect password.")
            else:
                print("Username not found.")
        elif choice == "0":
            print("Exiting program.")
            exit()
        else:
            print("Invalid choice. Please try again.")

# Function to view logs
def view_logs(users, username):
    print("\nLogin Logs:")
    for log in users[username]["logs"]:
        print(f"- {log}")

# Function to change password
def change_password(users, username):
    curr_password = input("Enter your current password:")
    if curr_password == users[username]["password"]:
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

# Main menu
def menu(users, username):
    while True:
        try:
            print("\nMenu:")
            print("2. View Logs")
            print("3. Change Password")
            print("4. Reset Password")
            print("0. Exit")

            choice = input("Enter your choice: ").strip()
            if choice == "2":
                view_logs(users, username)
            elif choice == "3":
                change_password(users, username)
            elif choice == "4":
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
    menu(users, logged_in_user)  # Show the menu only after successful login
