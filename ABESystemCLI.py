import getpass
from ABESystem import ABESystem


class ABESystemCLI:
    def __init__(self):
        self.system = ABESystem()
        self.logged_user = None
        self.user_key = None

    def register_user_interactive(self):
        if self.logged_user is None or self.logged_user["role"] != "admin":
            print("[!] Rejestracja może być przeprowadzona tylko przez admina.")
            return

        print("=== Rejestracja użytkownika ===")
        name = input("Nazwa użytkownika: ").strip()
        if self.system.db.user_exists(name):
            print("[!] Użytkownik już istnieje.")
            return

        password = getpass.getpass("Hasło: ")
        confirm = getpass.getpass("Potwierdź hasło: ")
        if password != confirm:
            print("[!] Hasła nie pasują.")
            return

        role = input("Rola (admin/user): ").strip().lower()
        if role not in ["admin", "user"]:
            print("[!] Nieprawidłowa rola.")
            return

        attr_str = input("Atrybuty (np. HR,manager): ")
        attributes = [a.strip() for a in attr_str.split(",") if a.strip()]
        user_key = self.system.create_user(name, password, role, attributes)
        print("[✓] Użytkownik zarejestrowany.")
        if user_key:
            print("[INFO] Wygenerowano klucz atrybutowy dla nowego użytkownika.")
            while True:
                save_path = input(
                    "Podaj ścieżkę do zapisu klucza użytkownika (np. output/user.key): "
                ).strip()
                if save_path:
                    try:
                        self.system.export_key_to_file(user_key, save_path)
                        print(
                            f"[✓] Klucz zapisany do {save_path}. Przekaż go użytkownikowi."
                        )
                        break
                    except Exception as e:
                        print(f"[!] Błąd zapisu klucza: {e}")
                else:
                    print("[!] Ścieżka nie może być pusta.")

    def login_interactive(self):
        print("=== Logowanie ===")
        name = input("Nazwa użytkownika: ").strip()
        password = getpass.getpass("Hasło: ")
        user = self.system.authenticate_user(name, password)
        if user:
            key_obj = None
            while True:
                key_path = input(
                    "Podaj ścieżkę do pliku z kluczem użytkownika (lub 'anuluj' by przerwać): "
                ).strip()
                if key_path.lower() == "anuluj":
                    print("[!] Logowanie przerwane (brak klucza).")
                    return None
                try:
                    key_obj = self.system.import_key_from_file(key_path)
                    print("[✓] Klucz zaimportowany.")
                    break
                except Exception as e:
                    print(f"[!] Błąd importu klucza: {e}")

            self.logged_user = user
            self.user_key = key_obj
            print(f"[✓] Zalogowano jako {name} ({user['role']})")
            return user
        else:
            print("[!] Błędne dane logowania.")
            return None

    def encrypt_file_interactive(self):
        print("=== Dodawanie pliku ===")
        path = input("Ścieżka do pliku: ").strip()
        label = input("Etykieta: ").strip()
        policy = input("Polityka dostępu (np. HR or manager): ").strip()
        try:
            self.system.encrypt_file(path, label, policy)
            print(f"[✓] Plik '{path}' zaszyfrowany i dodany jako '{label}'.")
        except Exception as e:
            print(f"[!] Błąd szyfrowania: {e}")

    def export_user_key_interactive(self):
        if not self.user_key:
            print("[!] Brak zaimportowanego klucza.")
            return

        path = input("Podaj ścieżkę do zapisu klucza: ").strip()
        try:
            self.system.export_key_to_file(self.user_key, path)
        except Exception as e:
            print(f"[!] Błąd eksportu klucza: {e}")

    def admin_menu(self):
        while True:
            print("\n=== MENU ADMINA ===")
            print("1. Dodaj użytkownika")
            print("2. Dodaj plik (zaszyfruj)")
            print("3. Odszyfruj plik")
            print("4. Lista użytkowników")
            print("5. Lista zaszyfrowanych plików")
            print("6. Dodaj użytkownikowi atrybuty")
            print("0. Wyloguj")
            choice = input("> ")
            try:
                if choice == "1":
                    self.register_user_interactive()
                elif choice == "2":
                    self.encrypt_file_interactive()
                elif choice == "3":
                    label = input("Etykieta pliku do odszyfrowania: ").strip()
                    output = input("Ścieżka do zapisu odszyfrowanego pliku: ").strip()
                    try:
                        decrypted = self.system.decrypt_by_label(self.user_key, label)
                        with open(output, "wb") as f:
                            f.write(decrypted)
                        print("[✓] Plik odszyfrowany i zapisany.")
                    except Exception as e:
                        print(f"[!] Błąd odszyfrowania: {e}")
                elif choice == "4":
                    users = self.system.list_users()
                    print("Użytkownicy:")
                    for u in users:
                        print(f" - {u[0]} | rola: {u[1]} | atrybuty: {u[2]}")
                elif choice == "5":
                    files = self.system.list_ciphertexts()
                    print("Zaszyfrowane pliki:")
                    for f in files:
                        print(f" - {f[0]} | polityka: {f[1]}")
                elif choice == '6':
                    username = input("Nazwa użytkownika: ")
                    attr_str = input("Atrybuty do dodania (oddzielone przecinkiem): ")
                    new_attrs = [a.strip() for a in attr_str.split(',')]
                    self.system.add_attributes_to_user(username, new_attrs)
                    print(f"[✓] Atrybuty {{{new_attrs}}} dodane do użytkownika {username}.")
                elif choice == "0":
                    self.logged_user = None
                    self.user_key = None
                    print("Wylogowano.")
                    break
                else:
                    print("Nieznana opcja.")
            except Exception as e:
                print(f"[!] Wystąpił błąd: {e}")

    def user_menu(self):
        while True:
            print("\n=== MENU UŻYTKOWNIKA ===")
            print("1. Dodaj plik (zaszyfruj)")
            print("2. Odszyfruj plik")
            print("3. Eksportuj swój klucz")
            print("0. Wyloguj")
            choice = input("> ")
            try:
                if choice == "1":
                    self.encrypt_file_interactive()
                elif choice == "2":
                    label = input("Etykieta pliku do odszyfrowania: ").strip()
                    output = input("Ścieżka do zapisu odszyfrowanego pliku (np. output/data.txt): ").strip()
                    try:
                        decrypted = self.system.decrypt_by_label(self.user_key, label)
                        with open(output, "wb") as f:
                            f.write(decrypted)
                        print("[✓] Plik odszyfrowany i zapisany.")
                    except Exception as e:
                        print(f"[!] Błąd odszyfrowania: {e}")
                elif choice == "3":
                    self.export_user_key_interactive()
                elif choice == "0":
                    self.logged_user = None
                    self.user_key = None
                    print("Wylogowano.")
                    break
                else:
                    print("Nieznana opcja.")
            except Exception as e:
                print(f"[!] Wystąpił błąd: {e}")

    def run(self):
        while True:
            print("\n=== System ABE ===")
            print("1. Logowanie")
            print("0. Wyjście")
            choice = input("> ")
            if choice == "1":
                if self.login_interactive():
                    if self.logged_user["role"] == "admin":
                        self.admin_menu()
                    else:
                        self.user_menu()
            elif choice == "0":
                print("Do widzenia!")
                break
            else:
                print("Nieznana opcja.")
