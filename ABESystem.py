import pickle
import os
import bcrypt
from charm.toolbox.pairinggroup import PairingGroup, GT, ZR, G1
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
from DatabaseManager import DatabaseManager

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from attributes import ALL_ATTRIBUTES


class ABESystem:
    def __init__(self):
        self.group = PairingGroup("SS512")
        self.cpabe = CPabe_BSW07(self.group)
        self.db = DatabaseManager()
        self.public_key = None
        self.master_key = None
        self.setup_system_keys()
        self.ensure_admin_exists()

    def setup_system_keys(self):
        self.public_key = self.db.load_system_public_key()
        self.load_master_key()
        if self.public_key is None or self.master_key is None:
            print("[INFO] Generowanie kluczy systemowych")
            self.public_key, self.master_key = self.cpabe.setup()
            self.db.save_system_public_key(self.public_key)
            self.save_master_key_to_file()


    def ensure_admin_exists(self):
        if not self.db.user_exists("admin"):
            print(
                "[INFO] Tworzenie domyślnego konta admina (login: admin, hasło: admin123)"
            )
            pw_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
            self.db.save_user("admin", pw_hash, "admin", ALL_ATTRIBUTES)
            self.export_key_to_file(
                self.generate_user_key(ALL_ATTRIBUTES), "output/admin.key"
            )

    def save_master_key_to_file(self):
        if not self.master_key:
            raise ValueError("Klucz główny nie został wygenerowany.")
        serialized = objectToBytes(self.master_key, self.group)
        with open("master_key.key", "wb") as f:
            pickle.dump(serialized, f)
        print("[✓] Klucz główny zapisany do pliku master_key.key")

    def load_master_key(self):
        if not os.path.exists("master_key.key"):
            print("[INFO] Plik master_key.key nie istnieje, generowanie nowego klucza głównego.")
            return None
        
        with open("master_key.key", "rb") as f:
            serialized = pickle.load(f)
        self.master_key = bytesToObject(serialized, self.group)
        if not self.master_key:
            raise ValueError("Nie udało się załadować klucza głównego.")
        print("[✓] Klucz główny załadowany z pliku master_key.key")

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
        user_key = self.generate_user_key(attributes)
        return user_key

    def delete_user(self, username):
        if not self.db.user_exists(username):
            raise ValueError(f"Użytkownik '{username}' nie istnieje.")
        self.db.delete_user(username)

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

        session_key = self.group.random(GT)

        abe_ciphertext = self.cpabe.encrypt(self.public_key, session_key, policy)
        session_key_bytes = self.group.serialize(session_key)
        aes_key = sha256(session_key_bytes).digest()

        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(file_bytes, AES.block_size))
        iv = cipher.iv

        data_to_store = {
            "abe": objectToBytes(abe_ciphertext, self.group),
            "aes": ct_bytes,
            "iv": iv
        }

        self.db.save_ciphertext(label, policy, pickle.dumps(data_to_store))

    def delete_file(self, label):
        _, ciphertext = self.db.get_ciphertext(label)
        if not ciphertext:
            raise ValueError(f"Nie znaleziono zaszyfrowanego pliku o etykiecie '{label}'.")
        self.db.delete_ciphertext(label)

    def decrypt_by_label(self, key_obj, label):
        policy, ciphertext_bytes = self.db.get_ciphertext(label)
        if not ciphertext_bytes:
            raise ValueError(f"Nie znaleziono danych o etykiecie: {label}")
        
        data = pickle.loads(ciphertext_bytes)
        abe_bytes = data["abe"]
        aes_ct = data["aes"]
        iv = data["iv"]

        abe_ciphertext = bytesToObject(abe_bytes, self.group)
        if not key_obj:
            raise ValueError("Klucz użytkownika nie został zaimportowany.")

        session_key = self.cpabe.decrypt(self.public_key, key_obj, abe_ciphertext) 
        if session_key is None or session_key == False:
            raise ValueError("Brak dostępu: nie można odszyfrować klucza sesji.")

        session_key_bytes = self.group.serialize(session_key)
        aes_key = sha256(session_key_bytes).digest()
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        file_bytes = unpad(cipher.decrypt(aes_ct), AES.block_size)
        return file_bytes

    def update_user_attributes(self, username, updated_attrs: list):
        """
        Aktualizuje atrybuty użytkownika, generuje nowy klucz i zapisuje go.
        """
        user = self.db.get_user(username)
        if not user:
            raise ValueError(f"Użytkownik '{username}' nie istnieje.")

        private_key = self.cpabe.keygen(self.public_key, self.master_key, updated_attrs)
        
        self.db.update_user_attributes(username, updated_attrs)
        self.db.save_user_private_key(username, private_key)

    def list_users(self):
        return self.db.list_users()

    def list_ciphertexts(self):
        return self.db.list_ciphertexts()
