import pickle
import os
import bcrypt
from charm.toolbox.pairinggroup import PairingGroup, GT, ZR, G1
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
from DatabaseManager import DatabaseManager


class ABESystem:
    def __init__(self):
        self.group = PairingGroup("SS512")
        self.cpabe = CPabe_BSW07(self.group)
        self.db = DatabaseManager()
        self.public_key, self.master_key = self.cpabe.setup()
        self.ensure_admin_exists()

    def ensure_admin_exists(self):
        if not self.db.user_exists("admin"):
            print(
                "[INFO] Tworzenie domyślnego konta admina (login: admin, hasło: admin123)"
            )
            pw_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
            self.db.save_user("admin", pw_hash, "admin", [])

    def export_key_to_file(self, key_obj, filepath):
        serialized = objectToBytes(key_obj, self.group)
        with open(filepath, "wb") as f:
            pickle.dump(serialized, f)
        print(f"[✓] Klucz wyeksportowany do {filepath}")

    def import_key_from_file(self, filepath):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Plik klucza '{filepath}' nie istnieje.")
        with open(filepath, "rb") as f:
            serialized = pickle.load(f)
        key_obj = bytesToObject(serialized, self.group)
        return key_obj

    def create_user(self, name, password, role, attributes):
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.db.save_user(name, pw_hash, role, attributes)
        if role != "admin":
            user_key = self.generate_user_key(attributes)
            return user_key
        return None

    def generate_user_key(self, attributes):
        return self.cpabe.keygen(self.public_key, self.master_key, attributes)

    def authenticate_user(self, name, password):
        user_data = self.db.get_user(name)
        if user_data:
            pw_hash, role, attr_str = user_data
            if bcrypt.checkpw(password.encode(), pw_hash):
                attributes = attr_str.split(",") if attr_str else []
                return {"name": name, "role": role, "attributes": attributes}

        return None

    def encrypt_file(self, filepath, label, policy):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Plik '{filepath}' nie istnieje.")

        with open(filepath, "rb") as f:
            file_bytes = f.read()

        file_hashed = self.group.hash(file_bytes, GT) # to się sypie
        ciphertext = self.cpabe.encrypt(self.public_key, file_hashed, policy)
        self.db.save_ciphertext(label, policy, objectToBytes(ciphertext, self.group))

    def decrypt_by_user(self, user, key_obj, label):
        policy, ciphertext_bytes = self.db.get_ciphertext(label)
        ciphertext = (
            bytesToObject(ciphertext_bytes, self.group) if ciphertext_bytes else None
        )
        if not ciphertext:
            raise ValueError(f"Nie znaleziono danych o etykiecie: {label}")
        if user["role"] == "admin":
            decrypted_bytes = self.cpabe.decrypt(
                self.public_key, self.master_key, ciphertext
            )
            return decrypted_bytes

        if not key_obj:
            raise ValueError("Klucz użytkownika nie został zaimportowany.")

        decrypted_bytes = self.cpabe.decrypt(self.public_key, key_obj, ciphertext)
        return decrypted_bytes

    def list_users(self):
        return self.db.list_users()

    def list_ciphertexts(self):
        return self.db.list_ciphertexts()
