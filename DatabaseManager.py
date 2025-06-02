import sqlite3
import os
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import objectToBytes, bytesToObject

DB_NAME = "data/abe_storage.db"


class DatabaseManager:
    def __init__(self):
        self.group = PairingGroup('SS512')
        self.conn = sqlite3.connect(DB_NAME)
        self.create_tables()
        os.makedirs("private_keys", exist_ok=True)

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                password_hash BLOB,
                role TEXT,
                attributes TEXT
            )"""
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ciphertexts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT UNIQUE,
                policy TEXT,
                blob BLOB
            )"""
        )
        self.conn.commit()

    def save_user(self, name, password_hash, role, attributes):
        cursor = self.conn.cursor()
        attrs_str = ",".join(attributes)
        cursor.execute(
            "INSERT OR REPLACE INTO users (name, password_hash, role, attributes) VALUES (?, ?, ?, ?)",
            (name, password_hash, role, attrs_str),
        )
        self.conn.commit()

    def delete_user(self, username):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM users WHERE name = ?", (username,))
        self.conn.commit()

        filepath = os.path.join("private_keys", f"{username}_priv.key")
        if os.path.exists(filepath):
            os.remove(filepath)

    def get_user(self, name):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT password_hash, role, attributes FROM users WHERE name=?", (name,)
        )
        return cursor.fetchone()

    def user_exists(self, name):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM users WHERE name=?", (name,))
        return cursor.fetchone() is not None

    def update_user_attributes(self, username, attributes):
        attr_str = ','.join(attributes)
        cursor = self.conn.cursor()
        cursor.execute('UPDATE users SET attributes = ? WHERE name = ?', (attr_str, username))
        self.conn.commit()

    def save_user_private_key(self, username, private_key):
        filepath = os.path.join("private_keys", f"{username}_priv.key")
        with open(filepath, 'wb') as f:
            f.write(objectToBytes(private_key, self.group))

    def load_user_private_key(self, username):
        filepath = os.path.join("private_keys", f"{username}_priv.key")
        if not os.path.exists(filepath):
            return None
        with open(filepath, 'rb') as f:
            return bytesToObject(f.read(), self.group)

    def list_users(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT name, role, attributes FROM users")
        return cursor.fetchall()

    def save_ciphertext(self, label, policy, ciphertext_bytes):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO ciphertexts (label, policy, blob) VALUES (?, ?, ?)",
            (label, policy, ciphertext_bytes),
        )
        self.conn.commit()

    def delete_ciphertext(self, label):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM ciphertexts WHERE label = ?", (label,))
        self.conn.commit()

    def get_ciphertext(self, label):
        cursor = self.conn.cursor()
        cursor.execute("SELECT policy, blob FROM ciphertexts WHERE label=?", (label,))
        row = cursor.fetchone()
        if row:
            policy = row[0]
            ct = row[1]
            return policy, ct
        return None, None

    def list_ciphertexts(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT label, policy FROM ciphertexts")
        return cursor.fetchall()
