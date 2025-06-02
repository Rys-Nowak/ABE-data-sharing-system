import unittest
from unittest.mock import patch, MagicMock, mock_open
from ABESystemCLI import ABESystemCLI

# test_ABESystemCLI.py

class TestABESystemCLI(unittest.TestCase):
    def setUp(self):
        self.cli = ABESystemCLI()
        self.cli.system = MagicMock()

    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("builtins.print")
    def test_register_user_interactive_admin(self, mock_print, mock_getpass, mock_input):
        self.cli.logged_user = {"name": "admin", "role": "admin"}
        mock_input.side_effect = [
            "testuser",      
            "user",         
            "HR,MANAGER",   
            "output/test.key" 
        ]
        mock_getpass.side_effect = ["pass123", "pass123"]
        self.cli.system.db.user_exists.return_value = False
        self.cli.system.create_user.return_value = "user_key_obj"
        self.cli.system.export_key_to_file.return_value = None

        self.cli.register_user_interactive()

        self.cli.system.create_user.assert_called_with("testuser", "pass123", "user", ["HR", "MANAGER"])
        self.cli.system.export_key_to_file.assert_called_with("user_key_obj", "output/test.key")
        self.assertTrue(any("[✓] Użytkownik zarejestrowany." in str(c) for c in mock_print.call_args_list))

    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("builtins.print")
    def test_register_user_interactive_not_admin(self, mock_print, mock_getpass, mock_input):
        self.cli.logged_user = {"name": "bob", "role": "user"}
        self.cli.register_user_interactive()
        self.assertTrue(any("Rejestracja może być przeprowadzona tylko przez admina" in str(c) for c in mock_print.call_args_list))

    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("builtins.print")
    def test_login_interactive_success(self, mock_print, mock_getpass, mock_input):
        mock_input.side_effect = ["alice", "output/alice.key"]
        mock_getpass.return_value = "alicepass"
        self.cli.system.authenticate_user.return_value = {"name": "alice", "role": "user", "attributes": ["HR"]}
        self.cli.system.import_key_from_file.return_value = "key_obj"

        user = self.cli.login_interactive()
        self.assertEqual(self.cli.logged_user["name"], "alice")
        self.assertEqual(self.cli.user_key, "key_obj")
        self.assertTrue(any("Zalogowano jako alice" in str(c) for c in mock_print.call_args_list))

    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("builtins.print")
    def test_login_interactive_fail(self, mock_print, mock_getpass, mock_input):
        mock_input.side_effect = ["alice"]
        mock_getpass.return_value = "wrongpass"
        self.cli.system.authenticate_user.return_value = None

        user = self.cli.login_interactive()
        self.assertIsNone(user)
        self.assertTrue(any("Błędne dane logowania" in str(c) for c in mock_print.call_args_list))

    @patch("builtins.input")
    @patch("builtins.print")
    def test_encrypt_file_interactive(self, mock_print, mock_input):
        mock_input.side_effect = ["input.txt", "label1", "HR or MANAGER"]
        self.cli.system.encrypt_file.return_value = None

        self.cli.encrypt_file_interactive()
        self.cli.system.encrypt_file.assert_called_with("input.txt", "label1", "HR or MANAGER")
        self.assertTrue(any("Plik 'input.txt' zaszyfrowany" in str(c) for c in mock_print.call_args_list))

    @patch("builtins.input")
    @patch("builtins.print")
    def test_export_user_key_interactive(self, mock_print, mock_input):
        self.cli.user_key = "key_obj"
        mock_input.return_value = "output/key.key"
        self.cli.system.export_key_to_file.return_value = None

        self.cli.export_user_key_interactive()
        self.cli.system.export_key_to_file.assert_called_with("key_obj", "output/key.key")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_export_user_key_interactive_no_key(self, mock_print, mock_input):
        self.cli.user_key = None
        self.cli.export_user_key_interactive()
        self.assertTrue(any("Brak zaimportowanego klucza" in str(c) for c in mock_print.call_args_list))

if __name__ == "__main__":
    unittest.main()