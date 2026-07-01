class ClientRecord:
    """Represents a client record in the system."""
    def __init__(self, client_id: bytes, name: str, public_key: bytes = None, last_seen: str = None):
        self.id = client_id          # 16 bytes (128 bit UUID)
        self.name = name             # up to 255 bytes, null-terminated ASCII
        self.public_key = public_key # 160 bytes
        self.last_seen = last_seen   # datetime string

    def __repr__(self):
        return f"ClientRecord(name={self.name}, id={self.id.hex()})"


class MessageRecord:
    """Represents a message record in the system."""
    def __init__(self, msg_id: int, to_client: bytes, from_client: bytes, msg_type: int, content: bytes = None):
        self.id = msg_id               # 4 bytes, auto-increment
        self.to_client = to_client     # 16 bytes
        self.from_client = from_client # 16 bytes
        self.type = msg_type           # 1 byte
        self.content = content or b''  # variable (BLOB)

    # Returns a readable string representation of the message record.
    def __repr__(self):
        return f"MessageRecord(id={self.id}, type={self.type}, from={self.from_client.hex()})"
