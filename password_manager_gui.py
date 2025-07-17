""" GUI PASSWORD MANAGER: Store all your passwords locally (CLI Backend with GUI Frontend) """

# NOTE: It will generate 'pswd.json' named file locally. Don't delete this file externally!

""" GUI PASSWORD MANAGER: Store all your passwords locally (CLI Backend with GUI Frontend) """

# NOTE: It will generate 'pswd.json' named file locally. Don't delete this file externally!

import base64
import os
import json
import tkinter as tk
from tkinter import scrolledtext

# ---------- Backend Functions (from CLI) ----------

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

def save_password_data(data):
    with open("pswd.json", "w") as file:
        json.dump(data, file, indent=4)

def set_master_key_if_needed():
    if not os.path.exists("pswd.json"):
        return True  # Need to set master key
    data = load_password_data()
    return "_master" not in data

# ---------- Custom Dialog Classes ----------

class ModernDialog:
    def __init__(self, parent, title, prompt, is_password=False):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x180")
        self.dialog.configure(bg="#2b2b2b")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog relative to the parent window
        parent.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 200
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 90
        self.dialog.geometry(f"+{x}+{y}")
        
        # Create main frame
        main_frame = tk.Frame(self.dialog, bg="#2b2b2b", padx=30, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Prompt label
        prompt_label = tk.Label(main_frame, text=prompt, font=("Segoe UI", 11), 
                               bg="#2b2b2b", fg="#ffffff")
        prompt_label.pack(pady=(0, 15))
        
        # Entry field
        self.entry = tk.Entry(main_frame, font=("Segoe UI", 11), width=30, 
                             relief=tk.FLAT, bd=5, bg="#404040", fg="#ffffff",
                             insertbackground="#ffffff",
                             show='•' if is_password else '')
        self.entry.pack(pady=(0, 20))
        self.entry.focus_set()
        
        # Button frame
        btn_frame = tk.Frame(main_frame, bg="#2b2b2b")
        btn_frame.pack()
        
        # OK button
        ok_btn = tk.Button(btn_frame, text="OK", command=self.ok_clicked,
                          font=("Segoe UI", 10, "bold"), bg="#3498db", fg="white",
                          relief=tk.FLAT, padx=20, pady=8, cursor="hand2")
        ok_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Cancel button
        cancel_btn = tk.Button(btn_frame, text="Cancel", command=self.cancel_clicked,
                              font=("Segoe UI", 10), bg="#6c757d", fg="white",
                              relief=tk.FLAT, padx=20, pady=8, cursor="hand2")
        cancel_btn.pack(side=tk.LEFT)
        
        # Bind Enter key
        self.entry.bind('<Return>', lambda e: self.ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())
    
    def ok_clicked(self):
        self.result = self.entry.get()
        self.dialog.destroy()
    
    def cancel_clicked(self):
        self.result = None
        self.dialog.destroy()
    
    def show(self):
        self.dialog.wait_window()
        return self.result

class ConfirmDialog:
    def __init__(self, parent, title, message):
        self.result = False
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x160")
        self.dialog.configure(bg="#2b2b2b")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog relative to the parent window
        parent.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 200
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 80
        self.dialog.geometry(f"+{x}+{y}")
        
        # Create main frame
        main_frame = tk.Frame(self.dialog, bg="#2b2b2b", padx=30, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Message label
        msg_label = tk.Label(main_frame, text=message, font=("Segoe UI", 11), 
                            bg="#2b2b2b", fg="#ffffff", wraplength=340)
        msg_label.pack(pady=(0, 20))
        
        # Button frame
        btn_frame = tk.Frame(main_frame, bg="#2b2b2b")
        btn_frame.pack()
        
        # Yes button
        yes_btn = tk.Button(btn_frame, text="Yes", command=self.yes_clicked,
                           font=("Segoe UI", 10, "bold"), bg="#e74c3c", fg="white",
                           relief=tk.FLAT, padx=20, pady=8, cursor="hand2")
        yes_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # No button
        no_btn = tk.Button(btn_frame, text="No", command=self.no_clicked,
                          font=("Segoe UI", 10), bg="#6c757d", fg="white",
                          relief=tk.FLAT, padx=20, pady=8, cursor="hand2")
        no_btn.pack(side=tk.LEFT)
        
        # Bind Escape key
        self.dialog.bind('<Escape>', lambda e: self.no_clicked())
    
    def yes_clicked(self):
        self.result = True
        self.dialog.destroy()
    
    def no_clicked(self):
        self.result = False
        self.dialog.destroy()
    
    def show(self):
        self.dialog.wait_window()
        return self.result

def ask_string(parent, title, prompt, is_password=False):
    dialog = ModernDialog(parent, title, prompt, is_password)
    return dialog.show()

def ask_yes_no(parent, title, message):
    dialog = ConfirmDialog(parent, title, message)
    return dialog.show()

# ---------- GUI Functions (adapted from CLI) ----------

def setup_master_key():
    if set_master_key_if_needed():
        show_info_message("Welcome! Please set up your master key.")
        
        for _ in range(3):
            key = ask_string(root, "Setup Master Key", "Set a master key for your password manager:", True)
            if not key:
                return False
            
            confirm_key = ask_string(root, "Setup Master Key", "Confirm your master key:", True)
            if not confirm_key:
                return False
                
            if key == confirm_key:
                encoded = base64.b64encode(key.encode()).decode()
                data = {"_master": encoded}
                save_password_data(data)
                show_success_message("Master key set successfully!")
                return True
            else:
                show_warning_message("Master keys didn't match. Please try again.")
        
        show_error_message("Failed to set master key after 3 attempts.")
        return False
    return True

def add_account():
    app_name = ask_string(root, "Add Account", "Enter app name:")
    if not app_name:
        return
    
    data = load_password_data()
    
    # Check for existing usernames
    existing_usernames = []
    if app_name in data:
        for user in data[app_name]:
            existing_usernames.append(user["username"])
    
    # Get unique username
    while True:
        username = ask_string(root, "Add Account", "Enter username:")
        if not username:
            return
        
        if username in existing_usernames:
            show_warning_message("Username already exists! Try another one.")
        else:
            break
    
    # Password confirmation with 3 attempts
    for _ in range(3):
        password = ask_string(root, "Add Account", "Enter password:", True)
        if not password:
            return
        password_check = ask_string(root, "Add Account", "Confirm your password:", True)
        if not password_check:
            return
        
        if password == password_check:
            break
        else:
            show_warning_message("Passwords didn't match. Please try again.")
    else:
        show_error_message("Failed 3 times. Account not added.")
        return
    
    # Encode and save
    encoded = base64.b64encode(password.encode()).decode()
    new_account = {"username": username, "password": encoded}
    
    data = load_password_data()
    if app_name in data:
        data[app_name].append(new_account)
    else:
        data[app_name] = [new_account]

    save_password_data(data)
    show_success_message(f"Account for '{app_name}' added successfully!")

def change_password():
    app_name = ask_string(root, "Change Password", "Enter app name:")
    if not app_name:
        return
    
    data = load_password_data()
    
    if app_name not in data:
        show_error_message("App doesn't exist in password manager!")
        return

    success = False
    for _ in range(3):
        username = ask_string(root, "Change Password", "Enter username:")
        if not username:
            return
        old_password = ask_string(root, "Change Password", "Enter current password:", True)
        if not old_password:
            return

        for user in data[app_name]:
            decoded = base64.b64decode(user["password"].encode()).decode()
            
            if user["username"] == username and decoded == old_password:
                for _ in range(3):
                    new_password = ask_string(root, "Change Password", "Enter new password:", True)
                    if not new_password:
                        return
                    confirm = ask_string(root, "Change Password", "Confirm new password:", True)
                    if not confirm:
                        return
                    
                    if new_password == confirm:
                        encoded = base64.b64encode(new_password.encode()).decode()
                        user["password"] = encoded
                        save_password_data(data)
                        show_success_message("Password changed successfully!")
                        return
                    else:
                        show_warning_message("Passwords did not match. Please try again.")
                return
        
        show_warning_message("Wrong username or password.")
    
    show_error_message("Failed 3 times. Please try again later!")

def show_password():
    app_name = ask_string(root, "View Password", "Enter app name:")
    if not app_name:
        return
    
    data = load_password_data()

    if app_name not in data:
        show_error_message("App doesn't exist in password manager!")
        return

    for _ in range(3):
        username = ask_string(root, "View Password", "Enter username:")
        if not username:
            return
        
        for user in data[app_name]:
            if user["username"] == username:
                decoded = base64.b64decode(user["password"].encode()).decode()
                show_info_message(f"Password for {username}: {decoded}")
                return
        
        show_warning_message("Username not found.")
    
    show_error_message("Failed 3 times. Please try again later!")

def show_all_passwords():
    data = load_password_data()
    
    if "_master" not in data:
        show_error_message("No master key found.")
        return
    
    master_key = data.get("_master")
    decoded_master = base64.b64decode(master_key.encode()).decode()
    
    key = ask_string(root, "Master Key Required", "Enter the master key:", True)
    if not key:
        return

    if key != decoded_master:
        show_error_message("Wrong master key!")
        return

    if not data or len(data) == 1:  # Only master key exists
        show_info_message("No passwords saved yet!")
        return

    # Create a new window for displaying all passwords
    show_window = tk.Toplevel(root)
    show_window.title("All Saved Passwords")
    show_window.geometry("600x500")
    show_window.configure(bg="#2b2b2b")
    show_window.resizable(True, True)
    
    # Center relative to parent
    root.update_idletasks()
    x = root.winfo_x() + (root.winfo_width() // 2) - 300
    y = root.winfo_y() + (root.winfo_height() // 2) - 250
    show_window.geometry(f"600x500+{x}+{y}")
    
    # Main frame
    main_frame = tk.Frame(show_window, bg="#2b2b2b", padx=20, pady=20)
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Title
    title_label = tk.Label(main_frame, text="All Saved Passwords", 
                          font=("Segoe UI", 16, "bold"), bg="#2b2b2b", fg="#ffffff")
    title_label.pack(pady=(0, 20))
    
    # Text area with scrollbar
    text_frame = tk.Frame(main_frame, bg="#2b2b2b")
    text_frame.pack(fill=tk.BOTH, expand=True)
    
    text_area = scrolledtext.ScrolledText(text_frame, font=("Consolas", 11), 
                                         bg="#404040", fg="#ffffff", relief=tk.FLAT, 
                                         bd=1, wrap=tk.WORD, insertbackground="#ffffff")
    text_area.pack(fill=tk.BOTH, expand=True)
    
    # Format and display data
    result = ""
    for app, accounts in data.items():
        if app == "_master":
            continue
        result += f"App: {app}\n"
        result += "─" * 40 + "\n"
        for user in accounts:
            decoded = base64.b64decode(user["password"].encode()).decode()
            result += f"     Username: {user['username']}\n"
            result += f"     Password: {decoded}\n\n"
        result += "\n"
    
    text_area.insert(tk.END, result)
    text_area.config(state=tk.DISABLED)
    
    # Close button
    close_btn = tk.Button(main_frame, text="Close", command=show_window.destroy,
                         font=("Segoe UI", 10, "bold"), bg="#e74c3c", fg="white",
                         relief=tk.FLAT, padx=25, pady=10, cursor="hand2")
    close_btn.pack(pady=(15, 0))

def delete_account():
    app_name = ask_string(root, "Delete Account", "Enter app name:")
    if not app_name:
        return
    
    data = load_password_data()
    
    if app_name not in data:
        show_error_message("App doesn't exist in password manager!")
        return
    
    for _ in range(3):
        username = ask_string(root, "Delete Account", "Enter username:")
        if not username:
            return
        password = ask_string(root, "Delete Account", "Enter password:", True)
        if not password:
            return
        
        for user in data[app_name]:
            decoded = base64.b64decode(user["password"].encode()).decode()
            
            if user["username"] == username and decoded == password:
                data[app_name].remove(user)
                
                # If no more accounts for this app, remove the app entirely
                if not data[app_name]:
                    del data[app_name]
                
                save_password_data(data)
                show_success_message(f"Account '{username}' deleted from '{app_name}' successfully!")
                return
        
        show_warning_message("Incorrect credentials.")
    
    show_error_message("Failed 3 times. Please try again later!")

def change_master_key():
    data = load_password_data()
    
    if "_master" not in data:
        show_error_message("No master key found.")
        return
    
    success = False
    for _ in range(3):
        old_key = ask_string(root, "Change Master Key", "Enter current master key:", True)
        if not old_key:
            return
        
        old_encoded = data["_master"]
        old_decoded = base64.b64decode(old_encoded.encode()).decode()
        
        if old_key == old_decoded:
            for _ in range(3):
                new_key = ask_string(root, "Change Master Key", "Enter new master key:", True)
                if not new_key:
                    return
                confirm_key = ask_string(root, "Change Master Key", "Confirm new master key:", True)
                if not confirm_key:
                    return
                
                if new_key == confirm_key:
                    encoded = base64.b64encode(new_key.encode()).decode()
                    data["_master"] = encoded
                    save_password_data(data)
                    show_success_message("Master key updated successfully!")
                    return
                else:
                    show_warning_message("Keys didn't match. Try again.")
            break
        else:
            show_warning_message("Wrong master key!")
    
    show_error_message("Failed 3 times. Try again later!")

def clear_password_manager():
    # First confirmation
    if not ask_yes_no(root, "Clear Password Manager", 
                      "Are you sure? This will delete everything permanently!"):
        show_info_message("Deletion cancelled.")
        return
    
    data = load_password_data()
    
    if "_master" not in data:
        show_error_message("No master key found.")
        return
    
    master_key = data.get("_master")
    decoded = base64.b64decode(master_key.encode()).decode()
    
    for _ in range(3):
        key = ask_string(root, "Master Key Required", "Enter the master key:", True)
        if not key:
            return
        
        if key == decoded:
            if os.path.exists("pswd.json"):
                os.remove("pswd.json")
                show_success_message("Password manager file deleted successfully!")
                # Show app closing message and then exit
                show_app_closing_message()
                return
            else:
                show_info_message("File doesn't exist.")
                return
        else:
            show_warning_message("Wrong master key.")
    
    show_error_message("Failed 3 times. Please try again later!")

def show_app_closing_message():
    """Show a special message when the app is closing after clearing data"""
    closing_window = tk.Toplevel(root)
    closing_window.title("Password Manager")
    closing_window.geometry("400x200")
    closing_window.configure(bg="#2b2b2b")
    closing_window.resizable(False, False)
    closing_window.transient(root)
    closing_window.grab_set()
    
    # Center the window relative to the parent
    root.update_idletasks()
    x = root.winfo_x() + (root.winfo_width() // 2) - 200
    y = root.winfo_y() + (root.winfo_height() // 2) - 100
    closing_window.geometry(f"+{x}+{y}")
    
    # Main frame
    main_frame = tk.Frame(closing_window, bg="#2b2b2b", padx=30, pady=30)
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Icon
    icon_label = tk.Label(main_frame, text="👋", font=("Segoe UI", 36), 
                         bg="#2b2b2b", fg="#ffffff")
    icon_label.pack(pady=(0, 15))
    
    # Message
    msg_label = tk.Label(main_frame, text="All data has been cleared.\nPassword Manager is now closing.", 
                        font=("Segoe UI", 12), bg="#2b2b2b", fg="#ffffff", 
                        justify=tk.CENTER)
    msg_label.pack(pady=(0, 20))
    
    # OK button
    ok_btn = tk.Button(main_frame, text="OK", command=lambda: [closing_window.destroy(), root.destroy()],
                      font=("Segoe UI", 10, "bold"), bg="#3498db", fg="white",
                      relief=tk.FLAT, padx=30, pady=10, cursor="hand2")
    ok_btn.pack()
    
    # Auto-close after 3 seconds
    closing_window.after(3000, lambda: [closing_window.destroy(), root.destroy()])
    
    closing_window.wait_window()

# ---------- Custom Message Boxes ----------

def show_message(title, message, msg_type="info"):
    msg_window = tk.Toplevel(root)
    msg_window.title(title)
    msg_window.geometry("380x160")
    msg_window.configure(bg="#2b2b2b")
    msg_window.resizable(False, False)
    msg_window.transient(root)
    msg_window.grab_set()
    
    # Center the window relative to the parent
    root.update_idletasks()
    x = root.winfo_x() + (root.winfo_width() // 2) - 190
    y = root.winfo_y() + (root.winfo_height() // 2) - 80
    msg_window.geometry(f"+{x}+{y}")
    
    # Main frame
    main_frame = tk.Frame(msg_window, bg="#2b2b2b", padx=25, pady=20)
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Icon and message
    icon_colors = {"info": "#3498db", "success": "#27ae60", "warning": "#f39c12", "error": "#e74c3c"}
    icons = {"info": "ℹ", "success": "✓", "warning": "⚠", "error": "✗"}
    
    msg_color = icon_colors.get(msg_type, "#3498db")
    icon = icons.get(msg_type, "ℹ")
    
    icon_label = tk.Label(main_frame, text=icon, font=("Segoe UI", 24), 
                         bg="#2b2b2b", fg=msg_color)
    icon_label.pack(pady=(0, 10))
    
    msg_label = tk.Label(main_frame, text=message, font=("Segoe UI", 11), 
                        bg="#2b2b2b", fg="#ffffff", wraplength=300)
    msg_label.pack(pady=(0, 15))
    
    # OK button
    ok_btn = tk.Button(main_frame, text="OK", command=msg_window.destroy,
                      font=("Segoe UI", 10, "bold"), bg=msg_color, fg="white",
                      relief=tk.FLAT, padx=25, pady=8, cursor="hand2")
    ok_btn.pack()
    
    msg_window.wait_window()

def show_info_message(message):
    show_message("Information", message, "info")

def show_success_message(message):
    show_message("Success", message, "success")

def show_warning_message(message):
    show_message("Warning", message, "warning")

def show_error_message(message):
    show_message("Error", message, "error")

def create_main_ui():
    """Create the main UI elements"""
    # Main container
    main_container = tk.Frame(root, bg="#1e1e1e", padx=40, pady=30)
    main_container.pack(fill=tk.BOTH, expand=True)

    # Header
    header_frame = tk.Frame(main_container, bg="#1e1e1e")
    header_frame.pack(pady=(0, 30))

    # Lock icon
    lock_icon = tk.Label(header_frame, text="🔐", font=("Segoe UI", 32), bg="#1e1e1e")
    lock_icon.pack()

    # Title
    title_label = tk.Label(header_frame, text="Password Manager", 
                          font=("Segoe UI", 24, "bold"), bg="#1e1e1e", fg="#ffffff")
    title_label.pack(pady=(5, 0))

    # Subtitle
    subtitle_label = tk.Label(header_frame, text="Secure • Local • Encrypted", 
                             font=("Segoe UI", 12), bg="#1e1e1e", fg="#b0b3b8")
    subtitle_label.pack(pady=(5, 0))

    # Buttons container
    buttons_frame = tk.Frame(main_container, bg="#1e1e1e")
    buttons_frame.pack(fill=tk.X)

    # Button configurations
    button_configs = [
        ("Add New Account", add_account, "#3498db", "➕"),
        ("Change Password", change_password, "#e67e22", "🔄"),
        ("View Password", show_password, "#27ae60", "👁"),
        ("View All Passwords", show_all_passwords, "#9b59b6", "📋"),
        ("Delete Account", delete_account, "#e74c3c", "🗑"),
        ("Change Master Key", change_master_key, "#f39c12", "🔑"),
        ("Clear Password Manager", clear_password_manager, "#c0392b", "🔥"),
        ("Exit", root.destroy, "#34495e", "🚪")
    ]

    # Create buttons
    for text, command, color, icon in button_configs:
        btn_frame = tk.Frame(buttons_frame, bg="#1e1e1e")
        btn_frame.pack(fill=tk.X, pady=6)
        
        btn = tk.Button(btn_frame, text=f"{icon}  {text}", command=command,
                       font=("Segoe UI", 12, "bold"), bg=color, fg="white",
                       relief=tk.FLAT, bd=0, padx=25, pady=12, cursor="hand2",
                       width=25)
        btn.pack()
        
        # Hover effects
        def on_enter(e, btn=btn, original_color=color):
            btn.configure(bg=darken_color(original_color))
        
        def on_leave(e, btn=btn, original_color=color):
            btn.configure(bg=original_color)
        
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)

    # Footer
    footer_frame = tk.Frame(main_container, bg="#1e1e1e")
    footer_frame.pack(side=tk.BOTTOM, pady=(20, 0))

    footer_label = tk.Label(footer_frame, text="Your passwords are stored locally with Base64 encoding", 
                           font=("Segoe UI", 10), bg="#1e1e1e", fg="#b0b3b8")
    footer_label.pack()

def darken_color(color):
    """Darken a hex color by 10%"""
    color = color.lstrip('#')
    rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
    darkened = tuple(max(0, int(c * 0.9)) for c in rgb)
    return f"#{darkened[0]:02x}{darkened[1]:02x}{darkened[2]:02x}"

# ---------- GUI Setup ----------

root = tk.Tk()
root.title("Password Manager")
root.geometry("500x700")
root.configure(bg="#1e1e1e")
root.resizable(False, False)

# Try to center the window
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width - 500) // 2
y = (screen_height - 700) // 2
root.geometry(f"500x700+{x}+{y}")

# Create the main UI first so it's visible during master key setup
create_main_ui()

# Initialize master key on startup
if not setup_master_key():
    root.destroy()
    exit()

if __name__ == "__main__":
    root.mainloop()
