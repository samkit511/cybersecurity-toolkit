import string
import random

def check_password_strength(password):
    length_criteria = len(password) >= 8
    uppercase_criteria = any(c.isupper() for c in password)
    lowercase_criteria = any(c.islower() for c in password)
    digit_criteria = any(c.isdigit() for c in password)
    special_criteria = any(c in string.punctuation for c in password)

    score = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, special_criteria])

    if score == 5:
        strength = "Very Strong"
    elif score == 4:
        strength = "Strong"
    elif score == 3:
        strength = "Moderate"
    elif score == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    feedback = []
    if not length_criteria:
        feedback.append("Password should be at least 8 characters long.")
    if not uppercase_criteria:
        feedback.append("Include uppercase letters.")
    if not lowercase_criteria:
        feedback.append("Include lowercase letters.")
    if not digit_criteria:
        feedback.append("Include numbers.")
    if not special_criteria:
        feedback.append("Include special characters.")

    return strength, feedback


def generate_strong_password(length=12):
    if length < 8:
        length = 8  # Enforce minimum length

    all_chars = string.ascii_letters + string.digits + string.punctuation

    # Guarantee each category appears at least once
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation),
    ]

    # Fill the rest with random chars
    password += random.choices(all_chars, k=length - 4)

    # Shuffle to avoid predictable pattern
    random.shuffle(password)

    return ''.join(password)


def main():
    print("Password Strength Checker & Generator")

    choice = input("Type 'check' to check a password or 'generate' to get a strong password: ").strip().lower()

    if choice == 'check':
        pwd = input("Enter the password to check: ")
        strength, feedback = check_password_strength(pwd)
        print(f"\nPassword strength: {strength}")
        if feedback:
            print("Suggestions to improve your password:")
            for f in feedback:
                print(f"- {f}")
        else:
            print("Your password looks strong!")
    
    elif choice == 'generate':
        try:
            length = int(input("Enter desired password length (minimum 8): "))
        except ValueError:
            length = 12
            print("Invalid input. Using default length 12.")
        strong_pwd = generate_strong_password(length)
        print(f"\nGenerated strong password: {strong_pwd}")

    else:
        print("Invalid choice. Please run the program again and type 'check' or 'generate'.")


if __name__ == "__main__":
    main()
