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
                log_in()
            elif choice =="2":
                pass
            elif choice =="3":
                pass
            elif choice =="4":
                pass
            elif choice =="5":
                pass
                break
            else :
                print("Invalid choice. Please try again.")
        except :
            print(f"An unexpected error occurred ")

def log_in():     
    username = input("Username:")
if __name__ == "__main__":
    main()    