class ValidationResult:
    def __init__(self, is_valid, message):
        self.is_valid = is_valid
        self.message = message

class UsernameValidator:
    def __init__(self, min_length=3, max_length=20, allow_special_chars=False):
        self.min_length = min_length
        self.max_length = max_length
        self.allow_special_chars = allow_special_chars
        
    def validate(self, username):
        if len(username) < self.min_length:
            return ValidationResult(False, f"Nazwa użytkownika musi mieć co najmniej {self.min_length} znaków.")
        if len(username) > self.max_length:
            return ValidationResult(False, f"Nazwa użytkownika nie może przekraczać {self.max_length} znaków.")
        if not self.allow_special_chars and not username.isalnum():
            return ValidationResult(False, "Nazwa użytkownika może zawierać tylko litery i cyfry.")
        
        return ValidationResult(True, "Nazwa użytkownika jest poprawna.")

class PasswordValidator:
    def __init__(self, min_length=8, max_length=20, require_uppercase=True, require_lowercase=True, require_digit=True, require_special_char=True):
        self.min_length = min_length
        self.max_length = max_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special_char = require_special_char
        
    def validate(self, password):
        if len(password) < self.min_length:
            return ValidationResult(False, f"Hasło musi mieć co najmniej {self.min_length} znaków.")
        if len(password) > self.max_length:
            return ValidationResult(False, f"Hasło nie może przekraczać {self.max_length} znaków.")
        if self.require_uppercase and not any(c.isupper() for c in password):
            return ValidationResult(False, "Hasło musi zawierać co najmniej jedną wielką literę.")
        if self.require_lowercase and not any(c.islower() for c in password):
            return ValidationResult(False, "Hasło musi zawierać co najmniej jedną małą literę.")
        if self.require_digit and not any(c.isdigit() for c in password):
            return ValidationResult(False, "Hasło musi zawierać co najmniej jedną cyfrę.")
        if self.require_special_char and not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password):
            return ValidationResult(False, "Hasło musi zawierać co najmniej jeden znak specjalny.")
        
        return ValidationResult(True, "Hasło jest poprawne.")