""" CLI PASSWORD MANAGER: Store all your passwords locally """

# NOTE: It will generate 'pswd.json' named file locally. Don't delete this file externally!

import base64
import os
import json
import getpass



# MASTER KEY SETUP

def set_master_key():
    if not os.path.exists("pswd.json"):
        print("Hello User!")
        key = getpass.getpass("Set a master key for your password manager: ")
        encoded = base64.b64encode(key.encode()).decode()
        data = {"_master": encoded}
        with open("pswd.json", "w") as file:
            json.dump(data, file, indent=4)
        print("\nMaster key set successfully!\n")




# CHANGE MASTER KEY

def change_master_key():
	data = load_password_data()
	if "_master" not in data:
		print("\nNo master key found.\n")
		return
	
	success = False
	attempts = 3

	while attempts > 0:
		old_key = getpass.getpass("Enter current master key: ")
		old_encoded = data["_master"]
		old_decoded = base64.b64decode(old_encoded.encode()).decode()
			
		if old_key == old_decoded:
			key_attempts = 3
			
			while key_attempts > 0:
				new_key = getpass.getpass("Enter new master key: ")
				confirm_key = getpass.getpass("Confirm new master key: ")
				
				if new_key == confirm_key:
					encoded = base64.b64encode(new_key.encode()).decode()
					data["_master"] = encoded	
					success = True
					break  
					
				else:
					print("\nKey didn't match. Try again\n")			
					key_attempts -= 1

			break  
			
		else:
			attempts -= 1
			print(f"\nWrong master key! Attempts left: {attempts}\n")

	if success:	
		with open("pswd.json", "w") as file:
			json.dump(data, file, indent=4)
		print("\nMaster key updated successfully.\n")
	else:
		print("\nFailed 3 times. Try again later!\n")





# EDGE CASE HANDLER

def load_password_data():
    if not os.path.exists("pswd.json"):
        return {}
    
    with open("pswd.json", "r") as file:
        content = file.read().strip()
        if not content:
            return {}  
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {} 




# ADD NEW ACCOUNT

def add_account():
	app_name = input("Enter app name: ")
	data = load_password_data()

	# making list of existing usernames under the app
	if app_name in data:
		existing_usernames = []
		
		for user in data[app_name]:
			existing_usernames.append(user["username"])
	else:
		existing_usernames = []

	# inputting unique username
	while True:
		username = input("\nEnter username: ")
		
		if username in existing_usernames:
			print("Username already exists! Try another one.\n")
		else:
			break

	# confirm password
	attempts = 3
	while attempts > 0:
		password = getpass.getpass("Enter password: ")
		pswd_check = getpass.getpass("Confirm your password: ")

		if pswd_check == password:
			break	
		else:
			attempts -= 1
			print(f"\nPasswords didn't match. Attempts left: {attempts}\n")

	if attempts == 0:
		print("Failed 3 times. Account not added.\n")
		return

	# Encode and save
	encoded = base64.b64encode(password.encode()).decode()
	new_account = {"username": username, "password": encoded}

	data = load_password_data() 

	if app_name in data:
		data[app_name].append(new_account)
	else:
		data[app_name] = [new_account]

	with open("pswd.json", "w") as file:
		json.dump(data, file, indent=4)

	print(f"\nAccount for '{app_name}' added successfully.\n")




# PASSWORD CHANGER

def pswd_changer():
	app_name = input("Enter app name: ")
	
	data = load_password_data()

	if app_name not in data:
		print("\nApp doesn't exist in password manager!\n")
	else:
		success = False
		attempts = 3
		
		while attempts > 0:
			username = input("\nEnter username: ")
			old_password = getpass.getpass("Enter current password: ")
			
			for user in data[app_name]:
				decoded = base64.b64decode(user["password"].encode()).decode()     # done changes here
				
				if user["username"] == username and decoded == old_password:       # done changes here
					pswd_attempts = 3
					
					while pswd_attempts > 0:
						password = getpass.getpass("Enter new password: ")
						password_check = getpass.getpass("Confirm your password: ")
						
						if password_check == password:
							encoded = base64.b64encode(password.encode()).decode()     # done changes here
							user["password"] = encoded      
							success = True
							break
						else:
							print("\nPasword didn't matched!\n")
							pswd_attempts -= 1
			if success:
				with open("pswd.json", "w") as file:
					json.dump(data, file, indent=4)
				print("\nPassword changed successfully!\n")
				break
				
			else:
				attempts -= 1
				print(f"\nWrong username or password. Attempts left: {attempts}\n")
		
		if success == False:
			print("\nFailed 3 times. Try again later!\n")




# SHOW PASSWORD FOR APP

def show_password():
	app_name = input("Enter app name: ")
	
	data = load_password_data()
		
	if app_name not in data:
		print("\nApp doesn't exist in password manager!\n")
		return
		
	else:
		found = False
		attempts = 3
		
		while attempts > 0:
			username = input("Enter username: ")
			
			for user in data[app_name]:
				if user["username"] == username:
					decoded = base64.b64decode(user["password"].encode()).decode()     # done changes here
					print(f"\npassword is: {decoded}\n")
					found = True
					break
			
			if found == True:
				break
				
			else:
				attempts -= 1
				print(f"\nUsername didn't matched. Attempts left: {attempts}\n")
					
		if found == False:
			print("\nFailed 3 times. Try again later!\n")

				

# SHOW ALL PASSWORD

def show_all():
	
	data = load_password_data()
	master_key = data.get("_master") 
	decoded = base64.b64decode(master_key.encode()).decode()                 
	key = getpass.getpass("Enter the Master Key: ")
	
	if key == decoded:
		data = load_password_data()
		
		if not data:
			print("\nNo password saved yet!\n")
			return
			
		print("\nAll saved passwords:\n")
		for app, accounts in data.items():
			if app == "_master":
				continue
			print(f"App: {app}")
			
			for user in accounts:
				decoded = base64.b64decode(user["password"].encode()).decode()     # done changes here
				print(f"     Username: {user['username']}")
				print(f"     Password: {decoded}\n")
		
	else:
		print("\nWrong master key!\n")
			


# CLEAR ACCOUNT USING USERNAME AND PASSWORD

def clear_account():
	app_name = input("Enter app name: ")
	
	data = load_password_data()
	
	if app_name not in data:
		print("\nApp doesn't exist in password manager!\n")
		return
	
	attempts = 3
	while attempts > 0:
		username = input("\nEnter username: ")
		password = getpass.getpass("Enter password: ")
		
		for user in data[app_name]:
			decoded = base64.b64decode(user["password"].encode()).decode()     # done changes here
			
			if user["username"] == username and decoded == password:
				data[app_name].remove(user)
				
				if not data[app_name]:   		# if there is no account in app, the app will be deleted here.
					del data[app_name]
					
				with open("pswd.json", "w") as file:
					json.dump(data, file, indent=4)
					
				print(f"Account '{username}' deleted from '{app_name}' successfully.\n")
				return
				
		attempts -= 1
		print(f"\nIncorrect credentials. Attempts left: {attempts}\n")
		
	print("\nFailed 3 times. Try again later!\n")
	
	
	
# CLEAR THE WHOLE FILE

def clear_pswd_manager():
	confirm = input("Are you sure? This will delete everything (y/n): ")
	if confirm != "y":
		print("\nDeletion cancelled.\n")
		return
	
	data = load_password_data()
	master_key = data.get("_master")     
	decoded = base64.b64decode(master_key.encode()).decode() 
	attempts = 3
	
	while attempts > 0:
		key = getpass.getpass("Enter the master key: ")
		if key == decoded:
			if os.path.exists("pswd.json"):
				os.remove("pswd.json")
				print("\nPassword manager file deleted successfully.\n")
				return
			else:
				print("\nFile already doesn't exist.\n")
				return
		
		else:
			attempts -= 1
			print(f"Wrong master key. Attempts left: {attempts}.\n")
			
	print("\nFailed 3 times. Try again later!\n")
	

# INPUT PART

set_master_key()
while True:
	print("\n---- PASSWORD MANAGER ----\n")
	print("1. Add new account")
	print("2. Change password")
	print("3. View password for app")
	print("4. View all passwords")
	print("5. Delete an account")
	print("6. Clear password manager")
	print("7. Change master key")
	print("8. Exit\n")
	choice = input("Enter your choice: ")
	
	if choice == "1":
		add_account()
	elif choice == "2":
		pswd_changer()
	elif choice == "3":
		show_password()
	elif choice == "4":
		show_all()
	elif choice == "5":
		clear_account()
	elif choice == "6":
		clear_pswd_manager()
		break
	elif choice == "7":
		change_master_key()
	elif choice == "8":
		break
	else:
		print("Invalid input!")


