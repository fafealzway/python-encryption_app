import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
import base64

# Function to encrypt the message
def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# Function to decrypt the message
def decrypt_message(enc_message, key):
    enc_message_bytes = base64.b64decode(enc_message.encode('utf-8'))
    nonce, tag, ciphertext = enc_message_bytes[:16], enc_message_bytes[16:32], enc_message_bytes[32:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Function to handle encryption
def encrypt():
    key = key_entry.get()
    message = message_entry.get("1.0", tk.END).strip()
    if len(key) != 16:
        messagebox.showerror("Error", "Key must be 16 characters long!")
        return
    enc_message = encrypt_message(message, key)
    encrypted_text.delete("1.0", tk.END)
    encrypted_text.insert(tk.END, enc_message)

# Function to handle decryption
def decrypt():
    key = key_entry.get()
    enc_message = encrypted_text.get("1.0", tk.END).strip()
    if len(key) != 16:
        messagebox.showerror("Error", "Key must be 16 characters long!")
        return
    try:
        decrypted_message = decrypt_message(enc_message, key)
        message_entry.delete("1.0", tk.END)
        message_entry.insert(tk.END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed: " + str(e))

# Create GUI
root = tk.Tk()
root.title("Message Encryption and Decryption")
root.configure(bg="#2C3E50")
root.geometry("400x400")

tk.Label(root, text="Enter Key (16 characters):", bg="#2C3E50", fg="white").pack(pady=10)
key_entry = tk.Entry(root, width=30)
key_entry.pack(pady=10)

tk.Label(root, text="Enter Message:", bg="#2C3E50", fg="white").pack(pady=10)
message_entry = tk.Text(root, height=5, width=40)
message_entry.pack(pady=10)

tk.Button(root, text="Encrypt", command=encrypt, bg="#27AE60", fg="white").pack(pady=5)
tk.Button(root, text="Decrypt", command=decrypt, bg="#E67E22", fg="white").pack(pady=5)

tk.Label(root, text="Encrypted Text:", bg="#2C3E50", fg="white").pack(pady=10)
encrypted_text = tk.Text(root, height=5, width=40)
encrypted_text.pack(pady=10)

root.mainloop()
`
