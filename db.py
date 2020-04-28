#! python3
import json
import time
import base64
import string
import random
import hashlib
import sqlite3
import threading

import Crypto
import Crypto.Signature.pss

uuid_charset = string.ascii_letters + string.digits + "-_"
pem_header = "-----BEGIN PUBLIC KEY-----"

class MIMSDBResponse:
    successful = False
    message = ""
    requested_data = None
    def __init__(self, successful, message):
        self.successful = successful
        self.message = message
        self.requested_data = None

# Use sqlite for now because of easy setup, could be changed to MySQL later
class MIMSDatabase:
    def __init__(self, db_path):
        self.threadlock = threading.Lock()
        self.db_path = db_path
        self.prepare_db()

    def prepare_db(self):
        # Creates the tables if not already existing, called on init
        with sqlite3.connect(self.db_path) as conn:
            # Table for users and their public key
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid TEXT NOT NULL UNIQUE,
                    pks TEXT NOT NULL,
                    pke TEXT NOT NULL,
                    rsa_sig TEXT NOT NULL
                );
            """)
            # An optional, client side encrypted private storage for users private key
            # The table is not linked to the uuid of a user for more security
            # retrieval_hash is not password, it's used to prevent download of private keys for offline password attacks
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS user_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    keys TEXT NOT NULL,
                    retrieval_hash TEXT NOT NULL,
                    salt TEXT NOT NULL
                );
            """)
            # Table for user public information, signed by the user's RSA key
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS user_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid TEXT NOT NULL UNIQUE,
                    display_name TEXT,
                    display_status TEXT,
                    display_icon TEXT,
                    rsa_sig TEXT NOT NULL,
                    FOREIGN KEY(uuid) REFERENCES users(uuid)
                );
            """)
            # Table for the end-to-end encrypted messages
            # timestamp is in time.time() format in Python
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_uuid TEXT NOT NULL,
                    recipient_uuid TEXT NOT NULL,
                    aes_key_encrypted TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    rsa_sig TEXT NOT NULL,
                    FOREIGN KEY(sender_uuid) REFERENCES users(uuid),
                    FOREIGN KEY(recipient_uuid) REFERENCES users(uuid)
                );
                CREATE INDEX IF NOT EXISTS recipient_uuid_idx ON messages(recipient_uuid);
            """)
            conn.commit()

    def check_username_exist(self, username):
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("SELECT 1 FROM user_keys WHERE username = ?;", (username))
                return cur.fetchone() != None

    def check_uuid_exist(self, uuid):
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("SELECT 1 FROM users WHERE uuid = ?;", (uuid,))
                return cur.fetchone() != None

    def register_uuid(self, pks_pem, pke_pem, rsa_sig):
        # Performs basic validation of the public keys
        # Does not verify pke_pem on server side
        if len(pks_pem) > 1024 or len(pke_pem) > 1024:
            return MIMSDBResponse(False, "Public key PEM too long (>1024) ")
        if not pks_pem.startswith(pem_header) or not pke_pem.startswith(pem_header):
            return MIMSDBResponse(False, "Public key PEM format invalid")
        request_params = [pks_pem.encode("utf-8"),pke_pem.encode("utf-8")]
        if (not rsa_verify(request_params, pks_pem, rsa_sig)):
            return MIMSDBResponse(False, f"Key verification error: {e}")
        # Creates entries on database
        uuid = ""
        with self.threadlock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    for retries in range(0,10):
                        try:
                            uuid = ''.join(random.choices(uuid_charset, k=12))
                            conn.execute("""
                            INSERT INTO users(uuid, pks, pke, rsa_sig)
                            VALUES(?,?,?,?,?,?)
                            """, (
                                    uuid,
                                    pks_pem,
                                    pke_pem,
                                    rsa_sig
                                )
                            )
                            successful = True
                            break
                        except sqlite3.IntegrityError as e:
                            last_error = e
                    if not successful:
                        raise sqlite3.IntegrityError(f"Uuid generation: IntegrityError after 10 retires")
                    conn.execute("INSERT INTO user_info(uuid) VALUES (?)", (uuid,))
                    conn.commit()
            except sqlite3.IntegrityError as e:
                return MIMSDBResponse(False, str(e))
        return MIMSDBResponse(True, uuid)

    def upload_keys(self, username, keys, retrieval_hash, salt):
        username = strip(username)
        if len(keys) > 8192:
            return MIMSDBResponse(False, "Key file too long (>8192) ")
        if username == "":
            return MIMSDBResponse(False, f"Username cannot be empty")
        # Hash the retrieval_hash once before storing
        # The retrieval_hash is NOT password, it is created by hasging a key derived from a key derivation function
        # It is used to verify if the key is correct before the encrypted private key
        # could be downloaded in order to prevent offline brute force attacks
        retrieval_hash = base64.b64encode(hashlib.sha256(base64.b64decode(retrieval_hash)).digest()).decode('ascii')
        with self.threadlock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                    INSERT INTO user_keys(username, keys, retrieval_hash, salt)
                    VALUES(?,?,?,?)
                    """, (username, keys, retrieval_hash, salt))
                return SIMDatabaseResponse(True, "Success")
            except sqlite3.IntegrityError:
                return SIMDatabaseResponse(False, "duplicated")

    # Parameters should all be in string format
    def request_public_keys(self, requesting_uuid, requester_uuid, rsa_sig):
        resp = self.verify_request([requesting_uuid, requester_uuid], requester_uuid, rsa_sig)
        if not resp.successful:
            return resp
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = self.dict_factory
                cur = conn.execute("SELECT pks, pke, rsa_sig FROM users WHERE uuid = ?", (requesting_uuid,))
                row = cur.fetchone()
                if row == None:
                    return MIMSDBResponse(False, "Requested uuid does not exist")
                response = MIMSDBResponse(True, "Success")
                response.requested_data = row
                return response

    # Parameters should all be in string format
    def request_public_info(self, requesting_uuid, requester_uuid, rsa_sig):
        resp = self.verify_request([requesting_uuid, requester_uuid], requester_uuid, rsa_sig)
        if not resp.successful:
            return resp
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = self.dict_factory
                cur = conn.execute("SELECT * FROM user_info WHERE uuid = ?", (requesting_uuid,))
                row = cur.fetchone()
                if row == None:
                    return MIMSDBResponse(False, "Requested uuid does not exist")
                response = MIMSDBResponse(True, "Success")
                response.requested_data = row
                return response

    def set_display_name(self, uuid, display_name, rsa_sig):
        resp = self.verify_request([uuid, display_name], uuid, rsa_sig)
        if not resp.successful:
            return resp
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("UPDATE user_info SET display_name = ? WHERE uuid = ?", display_name, uuid)
        return MIMSDBResponse(True, "Success")

    def set_display_status(self, uuid, display_status, rsa_sig):
        resp = self.verify_request([uuid, display_status], uuid, rsa_sig)
        if not resp.successful:
            return resp
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("UPDATE user_info SET display_status = ? WHERE uuid = ?", display_status, uuid)
        return MIMSDBResponse(True, "Success")

    def send_message(self, recipient_uuid, aes_key_encrypted, message, sender_uuid, rsa_sig):
        resp = self.verify_request([recipient_uuid, aes_key_encrypted, message, sender_uuid], sender_uuid, rsa_sig)
        if not resp.successful:
            return resp
        if not self.check_uuid_exist(recipient_uuid):
            return MIMSDBResponse(False, "Recipient uuid does not exist")
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO messages(recipient_uuid, aes_key_encrypted, message, sender_uuid, timestamp, rsa_sig)
                    VALUES(?,?,?,?,?,?)
                """, (
                        recipient_uuid,
                        aes_key_encrypted,
                        message,
                        sender_uuid,
                        time.time(),
                        rsa_sig
                     )
                )
        return MIMSDBResponse(True, "Success")

    # This does not do user verification and it is left for the server
    # Returns the time records are retrieved as message as well as the records
    # If specified, only return messages received later than after_timestamp
    def retrieve_messages(self, requesting_uuid, after_timestamp=0):
        time_retrieved = time.time()
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = self.dict_factory
                cur = conn.execute("""
                SELECT * FROM messages WHERE recipient_uuid = ? AND timestamp > ?
                """, (requesting_uuid, after_timestamp))
                messages = cur.fetchall()
                response = MIMSDBResponse(True, time_retrieved)
                response.requested_data = messages
                return response

    # Timestamp should be in Python time.time() format
    def delete_messages_older(self, requesting_uuid, timestamp):
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                    conn.execute("DELETE FROM messages WHERE id = ? AND timestamp < ?", (message['id'],timestamp))

    def get_key_salt(self, username):
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("""
                SELECT salt FROM user_keys WHERE username = ?
                """, (username))
                row = cur.fetchone()
                if row == None:
                    return MIMSDBResponse(False, "No entries found")
                response = MIMSDBResponse(True, "Success")
                response.requested_data = row[0]
                return response

    def download_keys(self, username, retrieval_hash):
        retrieval_hash = base64.b64encode(hashlib.sha256(base64.b64decode(retrieval_hash)).digest()).decode('ascii')
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("""
                SELECT keys FROM user_keys WHERE username = ? AND retrieval_hash = ?
                """, (username, retrieval_hash))
                row = cur.fetchone()
                if row == None:
                    return MIMSDBResponse(False, "No entries found")
                response = MIMSDBResponse(True, "Success")
                response.requested_data = row[0]
                return response

    def verify_request(self, request_params, sender_uuid, rsa_sig):
        pks_pem = ""
        with self.threadlock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("SELECT pks FROM users WHERE uuid = ?", (sender_uuid,))
                row = cur.fetchone()
                if row == None:
                    return MIMSDBResponse(False, "Invalid uuid")
                pks_pem = row[0]
        if (rsa_verify(request_params, pks_pem, rsa_sig)):
            return MIMSDBResponse(True, "Success")
        else:
            return MIMSDBResponse(False, f"Key verification error: {e}")

    # The request_params are signed by first sorting request_params by string alphabetically
    # Binary data are converted to base64 before signing
    def rsa_verify(self, request_params, pks_pem, rsa_sig):
        request_str = ''.join(sorted(map(str, request_params)))
        try:
            pks = Crypto.PublicKey.RSA.import_key(pks_pem)
            # RSA 2048 SHA256withRSA/PSS
            verifier = Crypto.Signature.pss.new(pks)
            hash = Crypto.Hash.SHA256.new(request_str.encode("utf-8"))
            signature = base64.b64decode(rsa_sig)
            verifier.verify(hash, signature)
            return True
        except (ValueError, IndexError, TypeError) as e:
            return False

    # Makes a dictionary from sqlite3 query results
    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d
