import sqlite3
import uuid
from datetime import datetime
import logging
from Server.models import ClientRecord, MessageRecord

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, db_name='defensive.db'):
        self.db_name = db_name
        self.conn = None
        self.init_database()

    # Opens a connection to the SQLite database and sets row_factory for named access.
    def connect(self):
        self.conn = sqlite3.connect(self.db_name)
        self.conn.row_factory = sqlite3.Row
        return self.conn

    # Closes the current database connection if open.
    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    # Creates the clients and messages tables if they don't exist,
    # and logs the current row counts on startup.
    def init_database(self):
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                ID BLOB PRIMARY KEY,
                Name TEXT NOT NULL UNIQUE,
                PublicKey BLOB,
                LastSeen TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                ToClient BLOB NOT NULL,
                FromClient BLOB NOT NULL,
                Type INTEGER NOT NULL,
                Content BLOB
            )
        ''')

        conn.commit()

        cursor.execute('SELECT COUNT(*) FROM clients')
        client_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM messages')
        message_count = cursor.fetchone()[0]

        logger.info(f"Database initialized successfully ({client_count} clients, {message_count} messages)")

    # Registers a new client with the given name and public key.
    # Generates a random UUID as the client ID.
    # Returns the new client ID bytes, or None if the name already exists.
    def register_client(self, name, public_key):
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute('SELECT ID FROM clients WHERE Name = ?', (name,))
            if cursor.fetchone():
                logger.warning(f"Username {name} already exists")
                return None

            client_id = uuid.uuid4().bytes
            last_seen = datetime.now().isoformat()

            cursor.execute('''
                INSERT INTO clients (ID, Name, PublicKey, LastSeen)
                VALUES (?, ?, ?, ?)
            ''', (client_id, name, public_key, last_seen))

            conn.commit()
            logger.info(f"Client {name} registered with ID {client_id.hex()}")
            return client_id

        except sqlite3.IntegrityError as e:
            logger.error(f"Database integrity error: {e}")
            return None
        finally:
            self.close()

    # Returns a list of ClientRecord objects for all clients except the given one.
    def get_all_clients(self, exclude_id):
        """Returns a list of ClientRecord objects excluding the given client."""
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute(
                'SELECT ID, Name, PublicKey, LastSeen FROM clients WHERE ID != ?',
                (exclude_id,)
            )
            return [
                ClientRecord(row['ID'], row['Name'], row['PublicKey'], row['LastSeen'])
                for row in cursor.fetchall()
            ]

        finally:
            self.close()

    # Returns the public key bytes for the given client ID, or None if not found.
    def get_client_public_key(self, client_id):
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute('SELECT PublicKey FROM clients WHERE ID = ?', (client_id,))
            row = cursor.fetchone()

            if row:
                return row['PublicKey']
            return None

        finally:
            self.close()

    # Returns a ClientRecord for the client with the given name, or None if not found.
    def get_client_by_name(self, name):
        """Returns a ClientRecord or None."""
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute(
                'SELECT ID, Name, PublicKey, LastSeen FROM clients WHERE Name = ?',
                (name,)
            )
            row = cursor.fetchone()

            if row:
                return ClientRecord(row['ID'], row['Name'], row['PublicKey'], row['LastSeen'])
            return None

        finally:
            self.close()

    # Updates the LastSeen timestamp for the given client to the current time.
    def update_last_seen(self, client_id):
        try:
            conn = self.connect()
            cursor = conn.cursor()

            last_seen = datetime.now().isoformat()
            cursor.execute(
                'UPDATE clients SET LastSeen = ? WHERE ID = ?',
                (last_seen, client_id)
            )
            conn.commit()

        finally:
            self.close()

    # Saves a new message to the database.
    # Returns the auto-generated message ID.
    def save_message(self, to_client, from_client, msg_type, content):
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO messages (ToClient, FromClient, Type, Content)
                VALUES (?, ?, ?, ?)
            ''', (to_client, from_client, msg_type, content))

            message_id = cursor.lastrowid
            conn.commit()

            logger.info(f"Message {message_id} saved from {from_client.hex()} to {to_client.hex()}")
            return message_id

        finally:
            self.close()

    # Returns a list of MessageRecord objects for all waiting messages of the given client,
    # ordered by message ID.
    def get_client_messages(self, client_id):
        """Returns a list of MessageRecord objects for the given client."""
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute('''
                SELECT ID, FromClient, Type, Content
                FROM messages
                WHERE ToClient = ?
                ORDER BY ID
            ''', (client_id,))

            return [
                MessageRecord(
                    row['ID'],
                    client_id,
                    row['FromClient'],
                    row['Type'],
                    row['Content'] if row['Content'] else b''
                )
                for row in cursor.fetchall()
            ]

        finally:
            self.close()

    # Deletes all messages addressed to the given client.
    # Logs the number of deleted messages.
    def delete_messages(self, client_id):
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute('DELETE FROM messages WHERE ToClient = ?', (client_id,))
            deleted_count = cursor.rowcount

            conn.commit()
            logger.info(f"Deleted {deleted_count} messages for client {client_id.hex()}")

        finally:
            self.close()

    # Returns True if a client with the given ID exists in the database, False otherwise.
    def client_exists(self, client_id):
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute('SELECT 1 FROM clients WHERE ID = ?', (client_id,))
            return cursor.fetchone() is not None

        finally:
            self.close()
