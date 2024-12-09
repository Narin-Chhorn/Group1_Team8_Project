import hashlib
# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
# User database (in a real-world application, use a database instead)
def login():
    try:
        username = input("Enter your username: ")
        if username in users:
            password = input("Enter your password: ")
            if hash_password(password) == users[username]["password"]:
                print("Login successful!")
                users[username]["logs"].append("Logged in on 2024-12-06")
            else:
                print("Incorrect password.")
        else:
            print("Username not found.")
    except Exception as e:
        print(f"An error occurred during login: {e}")
users = {
    "user1": {
        "password": hash_password("password123"),
        "logs": ["Logged in on 2024-12-01"]
             },
    "Narak": {
        "password": hash_password("@Rak1234"),
        "logs": ["logged in on today"]
        },

    }

def main():
    while True:
        try :
            print("\nMenu:")
            print("1. Login")
            print("2. View Logs")
            print("3. Change Password")
            print("4. Reset Password")
            print("5. Exit")
            choice=int(input("Enter the number:"))
            if choice == 1 :
                login()
            elif choice == 2 :
                pass
            elif choice == 3 :
                pass
            elif choice == 4 :
                pass
            elif choice == 5 :
                pass
                break
            else :
                print("Invalid choice. Please try again.")
        except :
            print("An unexpected error occurred ")
if __name__ == "__main__":
    main()    