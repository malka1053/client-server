#!/usr/bin/env python3

import socket
import threading
import logging
import sys
import os
import struct
from Server.database import Database
from Server.message_handler import MessageHandler
from Server.protocol import HEADER_SIZE, PAYLOAD_SIZE_OFFSET, PAYLOAD_SIZE_LENGTH, RECV_BUFFER_SIZE, SERVER_BACKLOG

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DEFAULT_PORT = 1357
PORT_INFO_FILE = 'myport.info'


class MessageUServer:
    def __init__(self, port=None):
        self.port = port or self._read_port()
        self.database = Database()
        self.message_handler = MessageHandler(self.database)
        self.running = False
        self.server_socket = None

    # Reads the port number from myport.info file.
    # If the file doesn't exist, creates it with the default port.
    # Returns the port number to use.
    def _read_port(self):
        try:
            if os.path.exists(PORT_INFO_FILE):
                with open(PORT_INFO_FILE, 'r') as f:
                    port = int(f.read().strip())
                    logger.info(f"Port {port} read from {PORT_INFO_FILE}")
                    return port
        except Exception as e:
            logger.warning(f"Could not read port from {PORT_INFO_FILE}: {e}")

        try:
            with open(PORT_INFO_FILE, 'w') as f:
                f.write(str(DEFAULT_PORT))
            logger.info(f"Created {PORT_INFO_FILE} with default port {DEFAULT_PORT}")
        except Exception as e:
            logger.error(f"Could not create {PORT_INFO_FILE}: {e}")

        return DEFAULT_PORT

    # Starts the server: binds to the port, listens for incoming connections,
    # and spawns a new daemon thread for each connected client.
    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(SERVER_BACKLOG)
            self.running = True

            logger.info(f"MessageU Server started on port {self.port}")
            logger.info("Waiting for connections...")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    logger.info(f"New connection from {address}")

                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()

                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")

        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)

        finally:
            self.stop()

    # Handles a single client connection in a dedicated thread.
    # Continuously receives requests and sends back responses
    # until the client disconnects or an error occurs.
    def _handle_client(self, client_socket, address):
        try:
            while True:
                data = self._receive_data(client_socket)
                if not data:
                    break

                response = self.message_handler.handle_request(data)

                if response:
                    client_socket.sendall(response)

        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")

        finally:
            try:
                client_socket.close()
                logger.info(f"Connection closed from {address}")
            except:
                pass

    # Receives a complete request from the client.
    # First reads the fixed-size header to determine payload size,
    # then reads the remaining payload bytes.
    # Returns the full raw request bytes, or None if the connection was closed.
    def _receive_data(self, client_socket):
        try:
            header_data = b''
            while len(header_data) < HEADER_SIZE:
                chunk = client_socket.recv(HEADER_SIZE - len(header_data))
                if not chunk:
                    return None
                header_data += chunk

            payload_size = struct.unpack('<I', header_data[PAYLOAD_SIZE_OFFSET:PAYLOAD_SIZE_OFFSET + PAYLOAD_SIZE_LENGTH])[0]

            payload_data = b''
            while len(payload_data) < payload_size:
                chunk = client_socket.recv(min(RECV_BUFFER_SIZE, payload_size - len(payload_data)))
                if not chunk:
                    break
                payload_data += chunk

            return header_data + payload_data

        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            return None

    # Gracefully stops the server by closing the server socket
    # and setting the running flag to False.
    def stop(self):
        logger.info("Stopping server...")
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logger.info("Server stopped")


def main():
    port = None
    reset_db = False

    for arg in sys.argv[1:]:
        if arg in ['--no-reset', '--keep', '-k']:
            reset_db = False
            logger.info("Keeping existing database")
        elif arg in ['--reset', '-r', '--clean']:
            reset_db = True
            logger.info("Database reset requested")
        else:
            try:
                port = int(arg)
            except ValueError:
                logger.error(f"Invalid argument: {arg}")
                logger.info("Usage: python3 server.py [port] [--reset|--no-reset]")
                sys.exit(1)

    if reset_db:
        db_file = 'defensive.db'
        if os.path.exists(db_file):
            os.remove(db_file)
            logger.info(f"Database deleted: {db_file} (fresh start)")
        else:
            logger.info("Starting with fresh database")

    server = MessageUServer(port)

    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("\nShutdown requested by user")
        server.stop()


if __name__ == '__main__':
    main()