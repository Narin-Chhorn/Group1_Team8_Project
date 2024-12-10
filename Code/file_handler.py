import hashlib
from datetime import datetime
import os

USER_FILE = "user.txt"  # File for user data
LOG_FILE = "log.txt"    # File for storing login and registration logs

class FileHandler:
    """
    Handles file operations for storing user data and logging activities.
    """

    # ---------- User Management ----------
    @staticmethod
    def load_users():
        """
        Load users from the user file (user.txt).
        Returns:
            list: A list of user dictionaries with username, hashed password, and email.
        """
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
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as file:
            file.write(f"[{timestamp}] {event_message}\n")
