import hashlib

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# User database (in a real-world application, use a secure database)
users = {
    "user1": {
        "password": hash_password("password123"),
        "logs": ["Logged in on 2024-12-01"]
    },
    "Narak": {
        "password": hash_password("@Rak1234"),
        "logs": ["Logged in on today"]
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
if __name__ == "__main__":
    logged_in_user = login()  # Ensure login first
    menu(logged_in_user)      # Show the menu only after successful login
