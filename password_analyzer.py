import re
import bcrypt
import secrets
import string
import json
import os
from pathlib import Path
from typing import Tuple, List

# Configuration
HASHES_FILE = "password_hashes.json"
MIN_LENGTH_WEAK = 8
MIN_LENGTH_STRONG = 12
COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "welcome",
    "password123",
    "123456789",
    "12345",
    "1234567",
    "12345678910",
    "qwertyuiop",
    "abc123",
    "monkey",
    "1234567890",
}


def load_password_hashes() -> List[str]:
    """Load stored password hashes from file."""
    if os.path.exists(HASHES_FILE):
        try:
            with open(HASHES_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            print(f"Warning: Could not read {HASHES_FILE}. Starting with empty history.")
            return []
    return []


def save_password_hashes(hashes: List[str]) -> None:
    """Save password hashes to file."""
    try:
        with open(HASHES_FILE, 'w') as f:
            json.dump(hashes, f, indent=2)
    except IOError as e:
        print(f"Error: Could not save password hashes: {e}")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt with a salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password_hash(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except (ValueError, TypeError):
        return False


def check_password_reuse(password: str, old_hashes: List[str]) -> bool:
    """Check if password matches any previously used password."""
    for old_hash in old_hashes:
        if verify_password_hash(password, old_hash):
            return True
    return False


def suggest_strong_password(length: int = 16) -> str:
    """Generate a random strong password."""
    # Ensure at least one of each type
    uppercase = secrets.choice(string.ascii_uppercase)
    lowercase = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    special = secrets.choice("!@#$%^&*()")
    
    # Fill the rest randomly
    charset = string.ascii_letters + string.digits + "!@#$%^&*()"
    remaining = ''.join(
        secrets.choice(charset) for _ in range(length - 4)
    )
    
    # Shuffle to avoid predictable patterns
    password_chars = list(uppercase + lowercase + digit + special + remaining)
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)


def analyze_password(password: str, old_hashes: List[str]) -> Tuple[int, str, List[str]]:
    """
    Analyze password strength and return score, strength rating, and feedback.
    
    Args:
        password: The password to analyze
        old_hashes: List of previously used password hashes
    
    Returns:
        Tuple of (score, strength, feedback_list)
    """
    score = 0
    feedback = []

    # Length Check
    if len(password) >= MIN_LENGTH_STRONG:
        score += 30
    elif len(password) >= MIN_LENGTH_WEAK:
        score += 20
    else:
        feedback.append(f"Use at least {MIN_LENGTH_WEAK} characters.")

    # Uppercase Check
    if re.search(r"[A-Z]", password):
        score += 15
    else:
        feedback.append("Add uppercase letters.")

    # Lowercase Check
    if re.search(r"[a-z]", password):
        score += 15
    else:
        feedback.append("Add lowercase letters.")

    # Numbers Check
    if re.search(r"\d", password):
        score += 15
    else:
        feedback.append("Add numbers.")

    # Special Characters Check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 15
    else:
        feedback.append("Add special characters.")

    # Common Password Check
    if password.lower() in common_passwords:
        score = max(score - 40, 0)
        feedback.append("Avoid common passwords.")

    # Password Reuse Check
    if check_password_reuse(password, old_hashes):
        score = max(score - 30, 0)
        feedback.append("Password has been used before.")

    # Determine Strength Rating
    if score >= 80:
        strength = "Strong"
    elif score >= 50:
        strength = "Moderate"
    else:
        strength = "Weak"

    return score, strength, feedback


def main():
    """Main program loop."""
    print("=" * 50)
    print("Password Strength Analyzer")
    print("=" * 50)
    
    # Load password history
    old_hashes = load_password_hashes()
    
    while True:
        password = input("\nEnter password (or 'quit' to exit): ").strip()
        
        if password.lower() == 'quit':
            print("Exiting...")
            break
        
        if not password:
            print("Password cannot be empty.")
            continue
        
        # Analyze password
        score, strength, feedback = analyze_password(password, old_hashes)
        
        # Display results
        print("\n" + "-" * 50)
        print("Password Analysis Results")
        print("-" * 50)
        print(f"Strength:  {strength}")
        print(f"Score:     {score}/100")
        
        if feedback:
            print("\nSuggestions:")
            for item in feedback:
                print(f"  • {item}")
        else:
            print("\n✓ Excellent password!")
        
        # Suggest stronger password if needed
        if strength != "Strong":
            print(f"\nSuggested Strong Password:")
            suggested = suggest_strong_password()
            print(f"  {suggested}")
            print("\n(Note: Do not store this in plain text. Use a password manager.)")
        
        # Ask if user wants to save
        if strength == "Strong":
            save_choice = input("\nSave this password to history? (y/n): ").strip().lower()
            if save_choice == 'y':
                new_hash = hash_password(password)
                old_hashes.append(new_hash)
                save_password_hashes(old_hashes)
                print("Password saved to history.")


if __name__ == "__main__":
    main()