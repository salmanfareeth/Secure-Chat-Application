# Secure Chat Application

This project is a secure chat application implemented in Python using socket programming and encryption techniques. The application includes a graphical user interface (GUI) for a better user experience. It supports secure communication, user authentication, end-to-end encryption, and a secure key exchange mechanism.

## Features

- **Secure Communication**: Implements encryption algorithms to secure the communication between the clients and the server using AES (Advanced Encryption Standard) and RSA (Rivest–Shamir–Adleman) algorithms.
- **User Authentication**: Develops a user authentication mechanism to ensure that only authorized users can join the chat.
- **End-to-End Encryption**: Ensures that messages exchanged between clients are only readable by the intended recipients.
- **Key Exchange**: Uses RSA encryption for securely exchanging AES keys between the server and clients.
- **GUI Interface**: Provides a user-friendly graphical interface for the chat application.
- **Connection and Disconnection Notifications**: Notifies all clients when a user connects or disconnects.
- **Server Logs in Chatbox**: Displays server logs and user connection/disconnection messages in the chatbox.

## Requirements

- Python 3.x
- `cryptography` package
- `tkinter` package

## Installation

1. **Clone the repository**:
    ```py
    git clone https://github.com/salmanfareeth/Secure-Chat-Application.git
    cd secure-chat-application
    ```

2. **Install the required packages**:
    ```py
    pip install cryptography
    ```

## Setup

1. **Generate RSA Keys** (if not already generated):
    ```bash
    python generate_rsa_keys.py
    ```

2. **Run the Server**:
    ```bash
    python main_server.py
    ```

3. **Run the Client**:
    ```bash
    python main_chat_client.py
    ```

## Usage

- **Server**:
  - The server handles user authentication, key exchange, and message forwarding.
  - It sends notifications to all clients when a user connects or disconnects.
  - Logs messages and connection/disconnection events and forwards them to all clients.

- **Client**:
  - The client connects to the server and authenticates the user.
  - Performs secure key exchange and communicates with end-to-end encryption.
  - Updates the chatbox with messages, connection/disconnection notifications, and server logs.

## Security

- **Encryption**:
  - Uses AES for encrypting the messages.
  - Uses RSA for encrypting the AES key during key exchange.
  
- **Authentication**:
  - Validates users based on predefined username and password pairs.

## File Structure

- `generate_rsa_keys.py`: Script to generate RSA keys.
- `main_server.py`: Script to run the server.
- `main_chat_client.py`: Script to run the client.
- `server_private_key.pem`: RSA private key for the server.
- `server_public_key.pem`: RSA public key for the server.

## Disclaimer

This application is developed for educational purposes and should not be used in production environments without further security enhancements.

## Developer Note

Tool developed and maintained by `salmanfareeth`.
This tool is in beta version.

## Contact

For any questions or feedback, please contact `salmanfareeth`.
