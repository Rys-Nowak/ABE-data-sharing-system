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


class ABESystem:
    def __init__(self):
        self.group = PairingGroup("SS512")
        self.cpabe = CPabe_BSW07(self.group)
        self.db = DatabaseManager()
        self.public_key, self.master_key = self.cpabe.setup()
        # self.setup()
        self.ensure_admin_exists()

    # def setup(self):
    #     if not os.path.exists("public_key.pkl") or not os.path.exists("master_key.pkl"):
    #         print("[INFO] Generowanie kluczy publicznego i głównego...")
    #         self.generate_keys()
    #         print("[✓] Klucze zostały wygenerowane.")
    #     else:
    #         print("[INFO] Klucze publiczny i główny już istnieją, wczytywanie...")
    #         with open("public_key.pkl", "rb") as f:
    #             serialized_pk = pickle.load(f)
    #         with open("master_key.pkl", "rb") as f:
    #             serialized_mk = pickle.load(f)
    #         self.public_key = bytesToObject(serialized_pk, self.group)
    #         self.master_key = bytesToObject(serialized_mk, self.group)
    #         print("[✓] Klucze zostały wczytane.")

    # def generate_keys(self):
    #     print("[INFO] Generowanie kluczy publicznego i głównego...")
    #     if os.path.exists("public_key.pkl") or os.path.exists("master_key.pkl"):
    #         print("[WARNING] Istnieją już klucze, nadpisywanie...")
    #         os.remove("public_key.pkl")
    #         os.remove("master_key.pkl")
    #     # Generowanie kluczy publicznego i głównego
    #     print("[INFO] Generowanie kluczy publicznego i głównego...")
    #     self.public_key, self.master_key = self.cpabe.setup()
    #     serialized_pk = objectToBytes(self.public_key, self.group)
    #     serialized_mk = objectToBytes(self.master_key, self.group)
    #     with open("public_key.pkl", "wb") as f:
    #         pickle.dump(serialized_pk, f)
    #     with open("master_key.pkl", "wb") as f:
    #         pickle.dump(serialized_mk, f)
    #     print("[✓] Klucze publiczny i główny zostały wygenerowane i zapisane.")

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

        # file_hashed = self.group.hash(file_bytes, G1) # to się sypie
        # ciphertext = self.cpabe.encrypt(self.public_key, file_hashed, policy)
        # self.db.save_ciphertext(label, policy, objectToBytes(ciphertext, self.group))
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

    def decrypt_by_user(self, user, key_obj, label):
        policy, ciphertext_bytes = self.db.get_ciphertext(label)
        if not ciphertext_bytes:
            raise ValueError(f"Nie znaleziono danych o etykiecie: {label}")
        
        data = pickle.loads(ciphertext_bytes)

        try: 
            abe_ciphertext = bytesToObject(data["abe"], self.group)
        except Exception as e:
            raise ValueError(f"Błąd podczas deserializacji danych: {e}")
        
        try:
            if user["role"] == "admin":
                session_key = self.cpabe.decrypt(self.public_key, self.master_key, abe_ciphertext)
            else:
                if not key_obj:
                    raise ValueError("Klucz użytkownika nie został zaimportowany.")
                session_key = self.cpabe.decrypt(self.public_key, key_obj, abe_ciphertext)
            if session_key is False or session_key is None:
                raise ValueError("Brak dostępu: nie można odszyfrować klucza sesji.")
        except Exception as e:
            raise ValueError(f"Błąd podczas odszyfrowywania klucza sesji: {e}")
        
        # if user["role"] == "admin":
            # print("Group object at decrypt:", id(self.group))
            # session_key = self.cpabe.decrypt(self.public_key, self.master_key, abe_ciphertext)
        # else:
            # if not key_obj:
                # raise ValueError("Klucz użytkownika nie został zaimportowany.")
            #TODO: This returns false, ValueError is caught later
            # that's why the whole decryption fails, i'm not sure why
            # print("Group object at decrypt:", id(self.group))
            # session_key = self.cpabe.decrypt(self.public_key, key_obj, abe_ciphertext) 
        # if session_key is None:
        #     raise ValueError("Brak dostępu: nie można odszyfrować klucza sesji.")

        # 4. Derive AES key from session key
        session_key_bytes = self.group.serialize(session_key)
        aes_key = sha256(session_key_bytes).digest()

        # 5. Decrypt the file bytes using AES
        # cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        cipher = AES.new(aes_key, AES.MODE_CBC, data["iv"])
        try:
            file_bytes = unpad(cipher.decrypt(data["aes"]), AES.block_size)
        except ValueError as e:
            raise ValueError(f"Nieprawidłowy AES: nie można odszyfrować danych. {e}")
        return file_bytes
        # ciphertext = (
        #     bytesToObject(ciphertext_bytes, self.group) if ciphertext_bytes else None
        # )
        # if not ciphertext:
        #     raise ValueError(f"Nie znaleziono danych o etykiecie: {label}")
        # if user["role"] == "admin":
        #     decrypted_bytes = self.cpabe.decrypt(
        #         self.public_key, self.master_key, ciphertext
        #     )
        #     return decrypted_bytes

        # if not key_obj:
        #     raise ValueError("Klucz użytkownika nie został zaimportowany.")

        # decrypted_bytes = self.cpabe.decrypt(self.public_key, key_obj, ciphertext)
        # return decrypted_bytes

    def list_users(self):
        return self.db.list_users()

    def list_ciphertexts(self):
        return self.db.list_ciphertexts()
