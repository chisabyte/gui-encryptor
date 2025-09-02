import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Author: Daniel Chisasura

# --- ENCRYPTION LOGIC ---
def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derives a secure 32-byte cryptographic key from a user's password and a salt.
    A Key Derivation Function (KDF) is used because human-memorable passwords are not
    random enough to be used directly as encryption keys. The KDF adds computational
    work (iterations) to make the key much stronger and resistant to brute-force attacks.
    """
    # Initialize the KDF.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 as the underlying hash function.
        length=32,                  # The desired length of the final key in bytes.
        salt=salt,                  # The salt adds unique randomness for each password.
        iterations=100000,          # A higher number of iterations is more secure.
        backend=default_backend()
    )
    # Derive the key from the password and then encode it to be URL-safe for Fernet.
    return base64.urlsafe_b64encode(kdf.derive(password))

def process_file(encrypt: bool):
    """
    Handles the entire file processing workflow: gets the password from the GUI,
    asks for a file, derives the key, and performs either encryption or decryption.
    """
    # Get the password from the GUI's password entry box.
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password cannot be empty.")
        return # Stop the function if no password was entered.

    # Open a file dialog to let the user choose a file.
    filepath = filedialog.askopenfilename()
    if not filepath:
        return # Stop the function if the user cancels the file dialog.

    try:
        # IMPORTANT: A fixed salt is used here for simplicity. In a real-world application,
        # you would generate a new random salt for each encryption and save it alongside
        # the encrypted file, so you can use it again for decryption.
        salt = b'\xfa\x8a\xbf\x1f\xdd\xb9\x91\x0f\xbf\xd0\xb2\xd7\xce\xc1\x8a\x17'
        
        # Derive the key from the password (encoded as bytes) and the salt.
        key = derive_key(password.encode(), salt)
        
        # Create a Fernet object with the derived key. This object will do the actual work.
        fernet = Fernet(key)

        # Open the selected file in binary read mode ('rb').
        with open(filepath, 'rb') as file:
            original_data = file.read()

        # --- ENCRYPT OR DECRYPT ---
        if encrypt:
            # Encrypt the data.
            processed_data = fernet.encrypt(original_data)
            # Define the output path for the new encrypted file.
            output_path = filepath + ".enc"
            action = "Encryption"
        else: # Decrypt
            # Decrypt the data. This will raise an InvalidToken error if the key (password) is wrong.
            processed_data = fernet.decrypt(original_data)
            # Define the output path for the decrypted file.
            output_path = filepath.replace(".enc", "")
            action = "Decryption"

        # Write the processed (encrypted or decrypted) data to the new file.
        with open(output_path, 'wb') as file:
            file.write(processed_data)

        # Show a success message to the user.
        messagebox.showinfo("Success", f"{action} successful!\nFile saved to: {output_path}")

    except Exception as e:
        # If anything goes wrong (e.g., wrong password for decryption), show an error message.
        messagebox.showerror("Error", f"An error occurred. Check your password or file type.\nDetails: {e}")


# --- GUI SETUP ---
# Create the main application window.
window = tk.Tk()
window.title("File Encryptor 🔒")
window.geometry("400x200")

# A Frame is a container widget to organize other widgets.
frame = tk.Frame(window, padx=10, pady=10)
frame.pack(expand=True)

# Create a text label for the password field.
password_label = tk.Label(frame, text="Enter Password:")
password_label.pack(pady=5)

# Create an Entry widget for the user to type their password.
# 'show="*"' makes it display asterisks instead of the actual characters.
password_entry = tk.Entry(frame, show="*", width=40)
password_entry.pack(pady=5)

# Create the "Encrypt File" button.
# The 'command' is set to a lambda function, which allows us to call our
# process_file function with the argument 'encrypt=True' when the button is clicked.
encrypt_button = tk.Button(frame, text="Encrypt File", command=lambda: process_file(encrypt=True))
encrypt_button.pack(side=tk.LEFT, padx=10, pady=20)

# Create the "Decrypt File" button, calling the same function but with 'encrypt=False'.
decrypt_button = tk.Button(frame, text="Decrypt File", command=lambda: process_file(encrypt=False))
decrypt_button.pack(side=tk.RIGHT, padx=10, pady=20)

# --- START GUI ---
# This line starts the tkinter event loop. The program will wait here for
# user interactions (like button clicks) until the window is closed.
window.mainloop()