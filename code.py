from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import messagebox

# Generate RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

# Encrypt the message using the public key
def encrypt_message(public_key, message):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message.hex()

# Decrypt the message using the private key
def decrypt_message(private_key, encrypted_message):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    decrypted_message = private_key.decrypt(
        bytes.fromhex(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# GUI setup
def on_encrypt():
    message = entry_message.get()
    if not message:
        print("Please enter a message to encrypt.")
        return

    private_key, public_key = generate_key_pair()
    encrypted_message = encrypt_message(public_key, message)
    
    # Print the encrypted message, private key, and public key in the terminal
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Public Key:\n{public_key.decode()}")
    print(f"Private Key:\n{private_key.decode()}")

    # Automatically populate the encrypted message and private key in the input fields
    entry_encrypted_message.delete("1.0", tk.END)
    entry_encrypted_message.insert(tk.END, encrypted_message)
    
    entry_private_key.delete("1.0", tk.END)
    entry_private_key.insert(tk.END, private_key.decode())

def on_decrypt():
    private_key = entry_private_key.get("1.0", tk.END).strip()
    encrypted_message = entry_encrypted_message.get("1.0", tk.END).strip()
    
    if not private_key:
        print("Please enter the private key.")
        return
    
    if not encrypted_message:
        print("Please enter the encrypted message.")
        return
    
    try:
        decrypted_message = decrypt_message(private_key.encode(), encrypted_message)
        print(f"Decrypted Message:\n{decrypted_message}")
    except Exception as e:
        print(f"Failed to decrypt the message.\nError: {str(e)}")

root = tk.Tk()
root.title("Message Encryption & Decryption Tool")

label_message = tk.Label(root, text="Enter the message you want to encrypt:")
label_message.pack()

entry_message = tk.Entry(root, width=40)
entry_message.pack()

btn_encrypt = tk.Button(root, text="Encrypt", command=on_encrypt)
btn_encrypt.pack()

label_private_key = tk.Label(root, text="Private key (automatically populated):")
label_private_key.pack()

entry_private_key = tk.Text(root, width=40, height=5)
entry_private_key.pack()

label_encrypted_message = tk.Label(root, text="Encrypted message (automatically populated):")
label_encrypted_message.pack()

entry_encrypted_message = tk.Text(root, width=40, height=5)
entry_encrypted_message.pack()

btn_decrypt = tk.Button(root, text="Decrypt", command=on_decrypt)
btn_decrypt.pack()

root.mainloop()
