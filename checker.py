import re
from cProfile import label
from tabnanny import check


def check_password(password):
    score = 0
    feedback = []

    #Rule 1
    if len(password) >= 12:
        score += 2

    elif len(password) >= 8:
        score += 1

    else:
        feedback.append('Use at least 8 character (12+ is best)')

    #Rule 2
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append('Add at least one uppercase letter (A-Z)')

    #Rule 3
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append('Add at least one lowercase letter (a-z)')

    #Rule 4
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append('Add at least one number character (0-9)')

    #Rule 5
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 2
    else:
        feedback.append('Add at least one special character ([!@#$%^&*(),.?":{}|<>])')

    return score, feedback

def calculate_entropy(password):
    pool = 0

    if re.search(r'[A-Z]', password):
        pool += 26

    if re.search(r'[a-z]', password):
        pool += 26

    if re.search(r'[0-9]', password):
        pool += 10

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        pool += 32

    if pool == 0:
        return "instantly"

    combinations = pool ** len(password)
    guesses_per_second = 100_000_000
    seconds_to_crack = combinations / guesses_per_second
    minutes = seconds_to_crack / 60
    hours = minutes / 60
    days = hours / 24
    years = days / 365

    #**Come back to edit when year prints '1 years'**#
    if years >= 1_000_000_000:
        return "billions of years (practically uncrackable)"
    elif years >= 1:
        return f"{round(years):,} years"
    elif days >= 1:
        return f"{round(days):,} days"
    elif hours >= 1:
        return f"{round(hours):,} hours"
    elif minutes >= 1:
        return f"{round(minutes):,} minutes"
    else:
        return "less than a minute"

def is_common(password):
    common_passwords = [
        "password", "123456", "qwerty", "letmein", "welcome",
        "admin", "monkey", "dragon", "abc123", "iloveyou",
        "sunshine", "password1", "football", "shadow", "123456789",
        "12345678", "12345", "1234567", "1234567890", "000000"
    ]
    return password.lower() in common_passwords

def strength_label(score):
    if score <= 1:
        return "Very Weak"
    elif score <= 3:
        return "Weak"
    elif score <= 5:
        return "Fair"
    elif score <= 6:
        return "Strong"
    else:
        return "Very Strong"

def main():
    print("=" * 40)
    print("    Password Strength Checker")
    print("=" * 40)

    password = input('\nPlease Enter your a password to check\n:')

    if is_common(password):
        print("\n[!] WARNING: This is one of the most common passwords ever used.")
        print("    It would be cracked instantly.")

    else:
        score, feedback = check_password(password)
        label = strength_label(score)
        time_to_crack = calculate_entropy(password)

        print(f"\nStrength     : {label}")
        print(f"Score        : {score}/8")
        print(f"Time to crack: {time_to_crack}")

        if feedback:
            print("\nSuggestions:")
            for tip in feedback:
                print(f"  -> {tip}")
        else:
            print("\n✓ No issues found — great password!")

if __name__ == "__main__":
    main()