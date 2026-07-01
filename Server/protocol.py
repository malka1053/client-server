# Request codes
REQ_REGISTER = 700
REQ_CLIENT_LIST = 701
REQ_PUBLIC_KEY = 702
REQ_SEND_MESSAGE = 703
REQ_WAITING_MESSAGES = 704
REQ_EXIT = 0

# Response codes
RES_REGISTRATION_SUCCESS = 2100
RES_CLIENT_LIST = 2101
RES_PUBLIC_KEY = 2102
RES_MESSAGE_SENT = 2103
RES_WAITING_MESSAGES = 2104
RES_GENERAL_ERROR = 9000

# Message types
MSG_TYPE_SYM_KEY_REQUEST = 1
MSG_TYPE_SYM_KEY_SEND = 2
MSG_TYPE_TEXT_MESSAGE = 3
MSG_TYPE_FILE = 4

# Protocol sizes
VERSION = 2
HEADER_SIZE = 23
CLIENT_ID_SIZE = 16
UUID_SIZE = 16
USERNAME_MAX_SIZE = 255
PUBLIC_KEY_SIZE = 160

# Header field offsets (used when parsing raw bytes without a full unpack)
# Header layout: client_id (16) + version (1) + code (2) + payload_size (4)
PAYLOAD_SIZE_OFFSET = 19   # byte offset of the payload_size field in the header
PAYLOAD_SIZE_LENGTH = 4    # size in bytes of the payload_size field

# Send message payload offsets
MSG_TYPE_SIZE = 1          # size in bytes of the message type field
MSG_CONTENT_SIZE_LENGTH = 4  # size in bytes of the content_size field
MSG_HEADER_SIZE = CLIENT_ID_SIZE + MSG_TYPE_SIZE + MSG_CONTENT_SIZE_LENGTH  # total send message header

# Server network constants
RECV_BUFFER_SIZE = 4096    # max bytes to read per recv() call
SERVER_BACKLOG = 5         # max number of queued incoming connections


class ProtocolError(Exception):
    pass


# Packs a response header: version (1 byte), code (2 bytes), payload_size (4 bytes).
# Returns the packed bytes in little-endian format.
def pack_header(version, code, payload_size):
    import struct
    return struct.pack('<BHI', version, code, payload_size)


# Parses the 23-byte request header from raw data.
# Returns a dict with client_id, version, code, and payload_size.
# Raises ProtocolError if the data is too short.
def unpack_request_header(data):
    import struct
    if len(data) < HEADER_SIZE:
        raise ProtocolError("Invalid header size")

    client_id = data[:CLIENT_ID_SIZE]
    version, code, payload_size = struct.unpack('<BHI', data[CLIENT_ID_SIZE:HEADER_SIZE])

    return {
        'client_id': client_id,
        'version': version,
        'code': code,
        'payload_size': payload_size
    }


# Builds a full response by prepending a header to the given payload.
# Returns the complete response bytes ready to send.
def pack_response(code, payload):
    header = pack_header(VERSION, code, len(payload))
    return header + payload


# Packs a single client entry for the client list response.
# Name is ASCII-encoded, null-padded to USERNAME_MAX_SIZE bytes.
def pack_client_info(client_id, name):
    import struct
    name_bytes = name.encode('ascii')[:254]
    name_bytes += b'\x00' * (USERNAME_MAX_SIZE - len(name_bytes))
    return client_id + name_bytes


# Packs a single message entry for the waiting messages response.
# Format: client_id (16) + message_id (4) + msg_type (1) + content_size (4) + content.
def pack_message_info(client_id, message_id, msg_type, content):
    import struct
    content_size = len(content)
    header = client_id + struct.pack('<IBI', message_id, msg_type, content_size)
    return header + content
