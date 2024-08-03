import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# User database (username:password)
users = {
    'user1': 'password1',
    'user2': 'password2'
}

# Load server private key
with open('server_private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

clients = []

def broadcast(message, _client_socket=None):
    for client in clients:
        if client != _client_socket:
            try:
                client.send(message)
            except:
                client.close()
                if client in clients:
                    clients.remove(client)

def authenticate(username, password):
    return users.get(username) == password

def handle_client(client_socket):
    global clients
    try:
        client_socket.send(b'Username: ')
        username = client_socket.recv(1024).decode()
        client_socket.send(b'Password: ')
        password = client_socket.recv(1024).decode()

        if authenticate(username, password):
            client_socket.send(b'Authenticated')
            encrypted_key = client_socket.recv(1024)
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            clients.append(client_socket)
            broadcast(f"{username} has connected.".encode(), client_socket)
            client_socket.send(b'Key exchange successful')

            while True:
                encrypted_message = client_socket.recv(1024)
                iv = encrypted_message[:16]
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                decryptor = cipher.decryptor()
                decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
                print(f"{username}: {decrypted_message.decode()}")
                broadcast(f"{username}: {decrypted_message.decode()}".encode(), client_socket)
        else:
            client_socket.send(b'Authentication failed')
            client_socket.close()
    except Exception as e:
        print(f"Error: {e}")
        client_socket.close()
        if client_socket in clients:
            clients.remove(client_socket)
            broadcast(f"{username} has disconnected.".encode(), client_socket)

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("Syed's ChatBox Server started. Waiting for connections...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()

