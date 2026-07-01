# Secure Messaging Client

A C++ secure messaging client that enables encrypted communication between users over a client-server architecture.

## Features

- User registration
- View registered clients
- Request public keys
- Exchange AES symmetric keys using RSA encryption
- Send encrypted text messages
- Send encrypted files
- Receive and decrypt messages and files

## Technologies

- C++
- Boost.Asio (Networking)
- Crypto++ (RSA & AES Encryption)

## Project Structure

- `src/` – Source files
- `include/` – Header files
- `docs/` – Project documentation

## Running

1. Configure the server address in `server.info`.
2. Build the project.
3. Run the client and register a new user.
4. Exchange keys with another client before sending encrypted messages or files.

## Authors

Developed as part of a Secure Programming course project.
