import struct
import logging
from Server.protocol import (
    HEADER_SIZE, CLIENT_ID_SIZE, USERNAME_MAX_SIZE, PUBLIC_KEY_SIZE,
    MSG_TYPE_SIZE, MSG_CONTENT_SIZE_LENGTH, MSG_HEADER_SIZE,
    REQ_REGISTER, REQ_CLIENT_LIST, REQ_PUBLIC_KEY,
    REQ_SEND_MESSAGE, REQ_WAITING_MESSAGES, REQ_EXIT,
    RES_REGISTRATION_SUCCESS, RES_CLIENT_LIST, RES_PUBLIC_KEY,
    RES_MESSAGE_SENT, RES_WAITING_MESSAGES, RES_GENERAL_ERROR,
    unpack_request_header, pack_response, pack_client_info, pack_message_info
)
from Server.database import Database
from Server.models import ClientRecord, MessageRecord

logger = logging.getLogger(__name__)


class MessageHandler:
    def __init__(self, database):
        self.db = database

    # Routes an incoming raw request to the appropriate handler based on the request code.
    # Returns the response bytes to send back to the client.
    def handle_request(self, data):
        try:
            if len(data) < HEADER_SIZE:
                logger.error("Request too short")
                return self._error_response()

            header = unpack_request_header(data)
            client_id = header['client_id']
            code = header['code']
            payload_size = header['payload_size']
            payload = data[HEADER_SIZE:HEADER_SIZE + payload_size]

            logger.info(f"Request code {code} from client {client_id.hex()}")

            if code == REQ_REGISTER:
                return self._handle_register(payload)
            elif code == REQ_CLIENT_LIST:
                return self._handle_client_list(client_id)
            elif code == REQ_PUBLIC_KEY:
                return self._handle_public_key(client_id, payload)
            elif code == REQ_SEND_MESSAGE:
                return self._handle_send_message(client_id, code, payload)
            elif code == REQ_WAITING_MESSAGES:
                return self._handle_waiting_messages(client_id)
            elif code == REQ_EXIT:
                return b''
            else:
                logger.error(f"Unknown request code: {code}")
                return self._error_response()

        except Exception as e:
            logger.error(f"Error handling request: {e}", exc_info=True)
            return self._error_response()

    # Registers a new client with the given username and public key from the payload.
    # Returns a success response with the new client ID, or an error response on failure.
    def _handle_register(self, payload):
        try:
            if len(payload) < USERNAME_MAX_SIZE + PUBLIC_KEY_SIZE:
                logger.error("Invalid registration payload size")
                return self._error_response()

            name_bytes = payload[:USERNAME_MAX_SIZE]
            public_key = payload[USERNAME_MAX_SIZE:USERNAME_MAX_SIZE + PUBLIC_KEY_SIZE]

            name = name_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')

            if not name:
                logger.error("Empty username")
                return self._error_response()

            client_id = self.db.register_client(name, public_key)

            if client_id is None:
                logger.error(f"Registration failed for {name}")
                return self._error_response()

            logger.info(f"Registration successful for {name}")
            return pack_response(RES_REGISTRATION_SUCCESS, client_id)

        except Exception as e:
            logger.error(f"Registration error: {e}", exc_info=True)
            return self._error_response()

    # Returns a list of all registered clients except the requesting client.
    # Also updates the requesting client's last seen timestamp.
    def _handle_client_list(self, client_id):
        try:
            self.db.update_last_seen(client_id)

            clients = self.db.get_all_clients(exclude_id=client_id)

            payload = b''
            for client in clients:
                payload += pack_client_info(client.id, client.name)

            logger.info(f"Sending list of {len(clients)} clients")
            return pack_response(RES_CLIENT_LIST, payload)

        except Exception as e:
            logger.error(f"Client list error: {e}", exc_info=True)
            return self._error_response()

    # Returns the public key of the target client specified in the payload.
    # Also updates the requesting client's last seen timestamp.
    def _handle_public_key(self, client_id, payload):
        try:
            self.db.update_last_seen(client_id)

            if len(payload) < CLIENT_ID_SIZE:
                logger.error("Invalid public key request payload")
                return self._error_response()

            target_client_id = payload[:CLIENT_ID_SIZE]

            public_key = self.db.get_client_public_key(target_client_id)

            if public_key is None:
                logger.error(f"Public key not found for {target_client_id.hex()}")
                return self._error_response()

            response_payload = target_client_id + public_key

            logger.info(f"Sending public key for {target_client_id.hex()}")
            return pack_response(RES_PUBLIC_KEY, response_payload)

        except Exception as e:
            logger.error(f"Public key error: {e}", exc_info=True)
            return self._error_response()

    # Retrieves all waiting messages for the requesting client, sends them,
    # then deletes them from the database.
    def _handle_waiting_messages(self, client_id):
        try:
            self.db.update_last_seen(client_id)

            messages = self.db.get_client_messages(client_id)

            payload = b''
            for msg in messages:
                msg_payload = pack_message_info(
                    msg.from_client,
                    msg.id,
                    msg.type,
                    msg.content
                )
                payload += msg_payload

            logger.info(f"Sending {len(messages)} waiting messages to {client_id.hex()}")

            if messages:
                self.db.delete_messages(client_id)

            return pack_response(RES_WAITING_MESSAGES, payload)

        except Exception as e:
            logger.error(f"Waiting messages error: {e}", exc_info=True)
            return self._error_response()

    # Saves a message from the sender to the target client in the database.
    # Returns a response with the target client ID and the new message ID.
    def _handle_send_message(self, from_client_id, code, payload):
        try:
            self.db.update_last_seen(from_client_id)

            if len(payload) < MSG_HEADER_SIZE:
                logger.error("Invalid send message payload")
                return self._error_response()

            to_client_id = payload[:CLIENT_ID_SIZE]
            msg_type = payload[CLIENT_ID_SIZE]
            content_size = struct.unpack("<I", payload[CLIENT_ID_SIZE + MSG_TYPE_SIZE:CLIENT_ID_SIZE + MSG_TYPE_SIZE + MSG_CONTENT_SIZE_LENGTH])[0]
            content = payload[MSG_HEADER_SIZE:MSG_HEADER_SIZE + content_size]

            if not self.db.client_exists(to_client_id):
                logger.error(f"Recipient {to_client_id.hex()} does not exist")
                return self._error_response()

            message_id = self.db.save_message(to_client_id, from_client_id, msg_type, content)

            response_payload = to_client_id + struct.pack('<I', message_id)

            logger.info(f"Message {message_id} sent from {from_client_id.hex()} to {to_client_id.hex()}")
            return pack_response(RES_MESSAGE_SENT, response_payload)

        except Exception as e:
            logger.error(f"Send message error: {e}", exc_info=True)
            return self._error_response()

    # Returns a general error response with an empty payload.
    def _error_response(self):
        return pack_response(RES_GENERAL_ERROR, b'')