import getpass
from ABESystem import ABESystem
from Validator import UsernameValidator, PasswordValidator


class ABESystemCLI:
    def __init__(self):
        self.system = ABESystem()
        self.username_validator = UsernameValidator()
        self.password_validator = PasswordValidator(
            min_length=6,
            require_uppercase=False,
            require_special_char=False
        )
        self.max_retries = 2
        self.logged_user = None
        self.user_key = None

    def register_user_interactive(self):
        if self.logged_user is None or self.logged_user["role"] != "admin":
            print("[!] Rejestracja może być przeprowadzona tylko przez admina.")
            return

        print("=== Rejestracja użytkownika ===")
        name = input("Nazwa użytkownika: ").strip()
        validation_result = self.username_validator.validate(name)
        retries = 0
        while not validation_result.is_valid:
            if retries == self.max_retries:
                print("[!] Przekroczono maksymalną liczbę prób.")
                return
            print(f"[!] {validation_result.message}")
            name = input("Nazwa użytkownika: ").strip()
            validation_result = self.username_validator.validate(name)
            retries += 1
            
        if self.system.db.user_exists(name):
            print("[!] Użytkownik już istnieje.")
            return

        password = getpass.getpass("Hasło: ")
        validation_result = self.password_validator.validate(password)
        retries = 0
        while not validation_result.is_valid:
            if retries == self.max_retries:
                print("[!] Przekroczono maksymalną liczbę prób.")
                return
            print(f"[!] {validation_result.message}")
            password = getpass.getpass("Hasło: ")
            validation_result = self.password_validator.validate(password)
            retries += 1
        
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

    def delete_user_interactive(self):
        if self.logged_user is None or self.logged_user["role"] != "admin":
            print("[!] Usuwanie użytkownika jest dostępne tylko dla admina.")
            return

        print("=== Usuwanie użytkownika ===")
        username = input("Podaj nazwę użytkownika do usunięcia: ").strip()
        if username == "admin":
            print("[!] Nie można usunąć konta administratora.")
            return

        if not self.system.db.user_exists(username):
            print("[!] Taki użytkownik nie istnieje.")
            return

        confirm = input(f"Czy na pewno chcesz usunąć użytkownika '{username}'? (tak/nie): ")
        if confirm.lower() != "tak":
            print("[INFO] Operacja anulowana.")
            return

        try:
            self.system.delete_user(username)
            print(f"[✓] Użytkownik '{username}' został usunięty.")
        except Exception as e:
            print(f"[!] Błąd podczas usuwania: {e}")

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

    def delete_file_interactive(self):
        if self.logged_user is None or self.logged_user["role"] != "admin":
            print("[!] Usuwanie plików dozwolone tylko dla administratora.")
            return

        print("=== Usuwanie zaszyfrowanego pliku ===")
        label = input("Podaj etykietę pliku do usunięcia: ").strip()
        try:
            self.system.delete_file(label)
            print(f"[✓] Plik o etykiecie '{label}' został usunięty.")
        except ValueError as e:
            print(f"[!] {e}")
        except Exception as e:
            print(f"[!] Wystąpił błąd podczas usuwania: {e}")

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
            print("2. Usuń użytkownika")
            print("3. Lista użytkowników")
            print("4. Zaktualizuj atrybuty użytkownika")
            print("5. Dodaj plik (zaszyfruj)")
            print("6. Odszyfruj plik")
            print("7. Usuń plik")
            print("8. Lista zaszyfrowanych plików")
            print("9. Eksportuj swój klucz")
            print("0. Wyloguj")
            choice = input("> ")
            try:
                if choice == "1":
                    self.register_user_interactive()
                elif choice == "2":
                    self.delete_user_interactive()
                elif choice == "3":
                    users = self.system.list_users()
                    print("Użytkownicy:")
                    for u in users:
                        print(f" - {u[0]} | rola: {u[1]} | atrybuty: {u[2]}")
                elif choice == "4":
                    username = input("Nazwa użytkownika: ").strip()
                    user = self.system.db.get_user(username)
                    if not user:
                        print("[!] Taki użytkownik nie istnieje.")
                        continue

                    current_attrs = user[2].split(",") if user[2] else []
                    print(f"Aktualne atrybuty: {current_attrs}")
                    print("Wybierz akcję:")
                    print("1. Dodaj")
                    print("2. Usuń")
                    print("3. Cofnij")
                    action_choice = input("> ").strip()

                    if action_choice == "1":
                        attr_str = input("Atrybuty do dodania (oddzielone przecinkiem): ")
                        new_attrs = [a.strip() for a in attr_str.split(',') if a.strip()]
                        updated_attrs = list(set(current_attrs + new_attrs))
                        self.system.update_user_attributes(username, updated_attrs)
                        print(f"[✓] Atrybuty dodane. Nowe atrybuty: {updated_attrs}")
                    elif action_choice == "2":
                        attr_str = input("Atrybuty do usunięcia (oddzielone przecinkiem): ")
                        remove_attrs = [a.strip() for a in attr_str.split(',') if a.strip()]
                        updated_attrs = [a for a in current_attrs if a not in remove_attrs]
                        self.system.update_user_attributes(username, updated_attrs)
                        print(f"[✓] Atrybuty usunięte. Nowe atrybuty: {updated_attrs}")
                    elif action_choice == "3":
                        print("Anulowano zmianę atrybutów.")
                    else:
                        print("[!] Nieznana akcja. Wybierz 1, 2 lub 3.")
                elif choice == "5":
                    self.encrypt_file_interactive()
                elif choice == "6":
                    label = input("Etykieta pliku do odszyfrowania: ").strip()
                    output = input("Ścieżka do zapisu odszyfrowanego pliku: ").strip()
                    try:
                        decrypted = self.system.decrypt_by_label(self.user_key, label)
                        with open(output, "wb") as f:
                            f.write(decrypted)
                        print("[✓] Plik odszyfrowany i zapisany.")
                    except Exception as e:
                        print(f"[!] Błąd odszyfrowania: {e}")
                elif choice == "7":
                    self.delete_file_interactive()
                elif choice == "8":
                    files = self.system.list_ciphertexts()
                    print("Zaszyfrowane pliki:")
                    for f in files:
                        print(f" - {f[0]} | polityka: {f[1]}")
                elif choice == "9":
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


    def user_menu(self):
        while True:
            print("\n=== MENU UŻYTKOWNIKA ===")
            print("1. Dodaj plik (zaszyfruj)")
            print("2. Odszyfruj plik")
            print("3. Eksportuj swój klucz")
            print("4. Lista użytkowników")
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
                elif choice == "4":
                    users = self.system.list_users()
                    print("Użytkownicy:")
                    for u in users:
                        print(f" - {u[0]} | rola: {u[1]} | atrybuty: {u[2]}")
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
