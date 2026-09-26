import re
import sqlite3
import hashlib
import secrets
import string
from datetime import datetime
from typing import List, Dict, Optional
from hashlib import pbkdf2_hmac

COMMON_PASSWORDS = {
    "password", "password123", "admin", "qwerty", "letmein", "welcome",
    "secret", "123456", "abc123", "iloveyou", "monkey", "dragon", "football",
    "passw0rd", "sunshine", "master", "login", "princess", "hello", "freedom"
}


class PasswordStrengthAnalyzer:
    def __init__(self, db_path: str = "password_history.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _hash_password(self, password: str, salt: Optional[str] = None) -> tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(16)
        dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
        return dk.hex(), salt

    def _normalize(self, value: str) -> str:
        return value.strip().lower()

    def _check_length(self, password: str) -> int:
        if len(password) < 8:
            return 0
        elif len(password) < 12:
            return 1
        elif len(password) < 16:
            return 2
        else:
            return 3

    def _check_complexity(self, password: str) -> int:
        score = 0
        if len(password) >= 8:
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 1
        if re.search(r"[^A-Za-z0-9]", password):
            score += 1

        # Penalize repeated characters and obvious patterns
        if re.search(r"(.)\1{2,}", password):
            score -= 1
        if re.search(r"123|456|789|abc|qwe|asd|password", self._normalize(password)):
            score -= 1
        if " " in password:
            score -= 1

        return max(0, min(5, score))

    def _check_uniqueness(self, password: str, previous_passwords: Optional[List[str]] = None) -> int:
        normalized = self._normalize(password)

        if normalized in COMMON_PASSWORDS:
            return 0

        # Check simple usage of common words and patterns
        if len(set(password)) < 3:
            return 0

        if previous_passwords:
            for old in previous_passwords:
                if self._normalize(old) == normalized:
                    return 0

        return 1

    def evaluate(self, password: str, previous_passwords: Optional[List[str]] = None) -> Dict[str, object]:
        length_score = self._check_length(password)
        complexity_score = self._check_complexity(password)
        uniqueness_score = self._check_uniqueness(password, previous_passwords)

        total_score = length_score + complexity_score + uniqueness_score

        # Rating logic
        if total_score <= 4:
            strength = "Weak"
        elif total_score <= 7:
            strength = "Moderate"
        elif total_score <= 9:
            strength = "Strong"
        else:
            strength = "Very Strong"

        feedback = []
        if len(password) < 12:
            feedback.append("Use at least 12 characters.")
        if not re.search(r"[A-Z]", password):
            feedback.append("Add uppercase letters.")
        if not re.search(r"[a-z]", password):
            feedback.append("Add lowercase letters.")
        if not re.search(r"\d", password):
            feedback.append("Add numbers.")
        if not re.search(r"[^A-Za-z0-9]", password):
            feedback.append("Add special characters.")
        if normalized := self._normalize(password):
            if normalized in COMMON_PASSWORDS:
                feedback.append("Avoid common passwords.")
        if re.search(r"(.)\1{2,}", password):
            feedback.append("Avoid repeated characters.")
        if not feedback:
            feedback.append("Good job! Your password is strong and well-balanced.")

        return {
            "password": password,
            "length_score": length_score,
            "complexity_score": complexity_score,
            "uniqueness_score": uniqueness_score,
            "total_score": total_score,
            "strength": strength,
            "feedback": feedback
        }

    def generate_stronger_password(self, base_word: str = "Secure") -> str:
        # Creates a stronger suggestion using random character groups
        word = base_word.capitalize()
        random_part = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*") for _ in range(8))
        return f"{word}!{random_part}"

    def add_old_password(self, user_id: str, password: str):
        hashed, salt = self._hash_password(password)
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO password_history (user_id, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
            (user_id, hashed, salt, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

    def check_password_reuse(self, user_id: str, password: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT password_hash, salt FROM password_history WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        conn.close()

        for stored_hash, salt in rows:
            candidate_hash, _ = self._hash_password(password, salt)
            if candidate_hash == stored_hash:
                return True
        return False


def demo():
    analyzer = PasswordStrengthAnalyzer()

    password = input("Enter a password: ")
    previous_passwords = ["Password123", "Summer2024", "MyPetDog!"]

    result = analyzer.evaluate(password, previous_passwords)
    print("\nPassword Strength Result:")
    print(f"Strength: {result['strength']}")
    print(f"Total Score: {result['total_score']}/10")
    print("Feedback:")
    for item in result["feedback"]:
        print(f" - {item}")

    suggestion = analyzer.generate_stronger_password("Sunset")
    print(f"\nSuggested Stronger Password: {suggestion}")

    # Optional: reuse check
    user = "demo_user"
    analyzer.add_old_password(user, "WeakPassword123!")
    reuse_exists = analyzer.check_password_reuse(user, "WeakPassword123!")
    print(f"\nPassword reuse check: {reuse_exists}")


if __name__ == "__main__":
    demo()
