import hashlib
from datetime import datetime
import os

# Folder for both user data and logs
DATA_AND_FILES_DIR = "Data and Files"  # Directory for both user data and log files

# Full paths for the user and log files
USER_FILE = os.path.join(DATA_AND_FILES_DIR, "user.txt")
LOG_FILE = os.path.join(DATA_AND_FILES_DIR, "logins.txt")

class FileHandler:
    """
    Handles file operations for storing user data and logging activities.
    """

    # Ensure the directory exists
    @staticmethod
    def ensure_directory():
        # Create "Data and Files" directory if it doesn't exist
        os.makedirs(DATA_AND_FILES_DIR, exist_ok=True)

    # ---------- User Management ----------
    @staticmethod
    def load_users():
        """
        Load users from the user file (user.txt).
        Returns:
            list: A list of user dictionaries with username, hashed password, and email.
        """
        FileHandler.ensure_directory()  # Ensure directory exists
        users = []
        if os.path.exists(USER_FILE):
            with open(USER_FILE, "r") as file:
                for line in file:
                    parts = line.strip().split("|")
                    if len(parts) == 3:
                        users.append({"username": parts[0], "password": parts[1], "email": parts[2]})
        return users

    @staticmethod
    def save_user(username, password, email):
        """
        Save a new user to the user file.
        Args:
            username (str): Username.
            password (str): Plain-text password to be hashed.
            email (str): User email.
        """
        FileHandler.ensure_directory()  # Ensure directory exists
        hashed_password = FileHandler.hash_password(password)
        with open(USER_FILE, "a") as file:
            file.write(f"{username}|{hashed_password}|{email}\n")
        FileHandler.log_event(f"User registered: {username}")

    @staticmethod
    def hash_password(password):
        """
        Hash a password using SHA-256.
        Args:
            password (str): The plain-text password.
        Returns:
            str: Hashed password.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def verify_password(input_password, stored_hashed_password):
        """
        Verify if the input password matches the stored hashed password.
        Args:
            input_password (str): Password entered by user.
            stored_hashed_password (str): Stored hashed password.
        Returns:
            bool: True if password matches, False otherwise.
        """
        return FileHandler.hash_password(input_password) == stored_hashed_password

    # ---------- Logging ----------
    @staticmethod
    def log_event(event_message):
        """
        Log events like registration or login attempts.
        Args:
            event_message (str): Description of the event.
        """
        FileHandler.ensure_directory()  # Ensure directory exists
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as file:
            file.write(f"[{timestamp}] {event_message}\n")

# Example usage:    

# Saving a user
FileHandler.save_user("Narin", "Narin@#98833995", "narinchhorn@gmail.com")

# Verifying password
users = FileHandler.load_users()
user = next((u for u in users if u["username"] == "Narin"), None)
if user and FileHandler.verify_password("Narin@#98833995", user["password"]):
    print("Password verified!")

# Logging an event
FileHandler.log_event("Test event logged.")
