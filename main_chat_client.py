import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import threading
import tkinter as tk
from tkinter import scrolledtext

# Load server public key
with open('server_public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())

# Generate AES key
aes_key = os.urandom(32)

def rsa_encrypt(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
    return encrypted_message

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    return decrypted_message.decode()

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Syed's Secure ChatBox")
        self.server_address = ('localhost', 12345)

        self.chat_window = scrolledtext.ScrolledText(root)
        self.chat_window.pack(padx=10, pady=10)

        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.pack(padx=10, pady=10)

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=10)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(self.server_address)

        # Authenticate
        self.socket.recv(1024)  # Username prompt
        self.socket.send(b'user1')
        self.socket.recv(1024)  # Password prompt
        self.socket.send(b'password1')
        auth_response = self.socket.recv(1024)
        if auth_response != b'Authenticated':
            self.chat_window.insert(tk.END, "Authentication failed.\n")
            self.socket.close()
            return

        # Key exchange
        encrypted_key = rsa_encrypt(aes_key, public_key)
        self.socket.send(encrypted_key)
        self.socket.recv(1024)  # Key exchange confirmation

        # Start a thread to receive messages from the server
        threading.Thread(target=self.receive_messages).start()

    def send_message(self):
        message = self.message_entry.get()
        encrypted_message = encrypt_message(message, aes_key)
        self.socket.send(encrypted_message)
        self.message_entry.delete(0, tk.END)
        self.chat_window.insert(tk.END, f"User1: {message}\n")

    def receive_messages(self):
        while True:
            try:
                message = self.socket.recv(1024).decode()
                self.chat_window.insert(tk.END, f"{message}\n")
            except:
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()

