import math
import string

COMMON_PASSWORDS = [
    '123456',
    'password',
    '123456789',
    '12345678',
    '12345',
    'qwerty',
    'abc123',
    'password1',
    'admin',
    'letmein',
    'welcome',
    'monkey'
]


def calculate_entropy(password: str) -> float:
    charset = 0

    if any(c.islower() for c in password):
        charset += 26

    if any(c.isupper() for c in password):
        charset += 26

    if any(c.isdigit() for c in password):
        charset += 10

    if any(c in string.punctuation for c in password):
        charset += len(string.punctuation)

    if any(c.isspace() for c in password):
        charset += 1

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)

    return round(entropy, 2)


def score_password(password: str) -> dict:
    score = 0
    length = len(password)
    entropy = calculate_entropy(password)

    # Rule-based scoring
    if length >= 8:
        score += 20

    if length >= 12:
        score += 10

    if any(c.islower() for c in password):
        score += 10

    if any(c.isupper() for c in password):
        score += 10

    if any(c.isdigit() for c in password):
        score += 10

    if any(c in string.punctuation for c in password):
        score += 10

    if entropy > 50:
        score += 20

    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 40)

    strength = ""

    if score < 40:
        strength = "Weak"

    elif score < 60:
        strength = "Moderate"

    elif score < 80:
        strength = "Strong"

    else:
        strength = "Very Strong"

    return {
        "password": password,
        "length": length,
        "entropy": entropy,
        "score": score,
        "verdict": strength
    }


def main():
    print("🔐 Password Strength Checker 🔐")

    password = input("Enter a password to check: ")

    result = score_password(password)

    print("\n--- Password Analysis ---")
    print(f"Length: {result['length']}")
    print(f"Entropy: {result['entropy']} bits")
    print(f"Score: {result['score']} / 100")
    print(f"Verdict: {result['verdict']}")


if __name__ == "__main__":
    main()