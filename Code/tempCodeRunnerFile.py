def main():
    while True:
        try:
            print("\nMenu:")
            print("1. Login")
            print("2. View Logs")
            print("3. Change Password")
            print("4. Reset Password")
            print("5. Exit")

            choice = input("Enter your choice: ").strip()

            if choice == "1":
                login()
            elif choice == "2":
                view_log()
            elif choice == "3":
                change_password()
            elif choice == "4":
                reset_password()
            elif choice == "5":
                print("Exiting the program. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()