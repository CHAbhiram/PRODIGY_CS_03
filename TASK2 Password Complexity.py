import re
import tkinter as tk
from tkinter import messagebox

def check_password_complexity(password):
    """
    Checks the complexity of a password
    """
    # Initialize a flag to indicate if the password is valid
    is_valid = True
    strength = "Weak"

    # Check if the password is at least 12 characters long
    if len(password) < 12:
        is_valid = False
    else:
        strength = "Strong"

    # Check if the password contains at least one uppercase letter
    if not re.search("[A-Z]", password):
        is_valid = False
    else:
        if strength == "Strong":
            strength = "Excellent"

    # Check if the password contains at least one lowercase letter
    if not re.search("[a-z]", password):
        is_valid = False
    else:
        if strength == "Strong":
            strength = "Excellent"

    # Check if the password contains at least one digit
    if not re.search("[0-9]", password):
        is_valid = False
    else:
        if strength == "Strong":
            strength = "Excellent"

    # Check if the password contains at least one special character
    if not re.search("[!@#$%^&*()_+=-{};:'<>,./?]", password):
        is_valid = False
    else:
        if strength == "Strong":
            strength = "Excellent"

    return is_valid, strength

def check_password():
    password = password_entry.get()
    is_valid, strength = check_password_complexity(password)
    if is_valid:
        messagebox.showinfo("Password Strength", f"Password is {strength}")
    else:
        messagebox.showerror("Password Strength", "Password is weak. Please try again.")

root = tk.Tk()
root.title("Password Strength Checker")

password_label = tk.Label(root, text="Enter a password:")
password_label.pack()

password_entry = tk.Entry(root, show="*")
password_entry.pack()

check_button = tk.Button(root, text="Check Password", command=check_password)
check_button.pack()

root.mainloop()