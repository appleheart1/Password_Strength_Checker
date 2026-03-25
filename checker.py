import re
from datetime import date

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

    #Rule 6
    if re.search(r'(.)\1{2,}', password):
        score -=1
        feedback.append('Avoid repeating characters (e.g. aaa or 111)')
    elif len (password) >=8:
        score += 1

    #prevent score from going negative
    score = max(score, 0)
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


    if years >= 1_000_000_000:
        return "billions of years (practically uncrackable)"

    elif round(years) >= 1:
        year_word = "year" if round(years) == 1 else "years"
        return f"{round(years):,} {year_word}"

    elif round(days) >= 1:
        day_word = "day" if round(days) == 1 else "days"
        return f"{round(days):,} {day_word}"

    elif round(hours) >= 1:
        hour_word = "hour" if round(hours) == 1 else "hours"
        return f"{round(hours):,} {hour_word}"

    elif round(minutes) >= 1:
        minute_word = "minute" if round(minutes) == 1 else "minutes"
        return f"{round(minutes):,} {minute_word}"

    else:
        return "less than a minute"

def is_common(password):
    try:
        with open("10k-most-common.txt", 'r') as f:
            common_pswd = f.read().split('\n')
            for i in common_pswd:
                if i.strip() == password.lower():
                    return True
            return False
    except FileNotFoundError:
        return False

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

def expand_birthday(birthday):
    variations = [birthday]

    #only process if it looks like a date with slashes e.g. 12/12/2000
    if '/' in birthday:
        parts = birthday.split('/')

    elif len(birthday) == 8 and birthday.isdigit():
        parts = [birthday[0:2], birthday[2:4], birthday[4:8]]

    else:
        parts = []

    if len(parts) == 3:
        day, month, year = parts
        short_year = year[-2:] #2006 -> 06

        month_names = {
            '01': 'january', '02': 'february', '03': 'march',
            '04': 'april', '05': 'may', '06': 'june',
            '07': 'july', '08': 'august', '09': 'september',
            '10': 'october', '11': 'november', '12': 'december'
        }

        month_short = {
            '01': 'jan', '02': 'feb', '03': 'mar',
            '04': 'apr', '05': 'may', '06': 'jun',
            '07': 'jul', '08': 'aug', '09': 'sep',
            '10': 'oct', '11': 'nov', '12': 'dec'
        }

        variations += [
            day, month, year, short_year,
            day + month,
            day + month + year,
            day + month + short_year,
            month + day + year,
            year + month + day,
            day + month_names.get(month, ''),
            day + month_short.get(month, ''),
            month_names.get(month, ''),
            month_short.get(month, ''),
        ]
    variations = list(dict.fromkeys(variations))
    return [v for v in variations if v]

def contains_personal_info(password, personal_info):
    matches = []
    for info in personal_info:
        if info and len(info) >= 2 and info in password.lower():
            if info not in matches: #only add if not already in the list
                matches.append(info)
    if matches:
        return True, matches
    return False, []

def calculate_age(birthday):
    today = date.today()

    if '/' in birthday:
        parts = birthday.split('/')
        day, month, year = int(parts[0]), int(parts[1]), int(parts[2])
    elif len(birthday) == 8 and birthday.isdigit():
        day = int(birthday[0:2])
        month = int(birthday[2:4])
        year = int(birthday[4:8])
    else:
        return None

    try:
        dob = date(year, month, day)
    except ValueError:
        return None

    age = today.year - dob.year

    if (today.month, today.day) < (dob.month, dob.day):
        age -= 1

    return age

def main():
    print("=" * 40)
    print("    Password Strength Checker")
    print("=" * 40)
    full_name = input("\nPlease enter your First and last name (first last)\n:").lower()
    name_parts = full_name.split()

    birthday = input("\nPlease enter your birthdate (DD/MM/YYYY or DDMMYYYY)\n:")

    birthday_variations = expand_birthday(birthday)

    age = calculate_age(birthday)
    if age is not None:
        age_str = str(age)
    else:
        age_str = input("\nCould not calculate age — please enter it manually\n:").lower()

    personal_info = name_parts + [age_str] + birthday_variations



    while True:
        password = input('\nPlease Enter your a password to check (or Q/q to quit)\n:')

        if password.lower() == 'q':
            print ("\nGoodbye!")
            break
        # check password against user's personal information
        found, matched = contains_personal_info(password, personal_info)

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

            if found:
                print(f"\n[!] WARNING: Your password contains personal information:")
                print(f"    Found: {', '.join(matched)}")
                print(f"    Attackers try names, birthdays and ages first!")
            if feedback:
                print("\nSuggestions:")
                for tip in feedback:
                    print(f"  -> {tip}")
            if not found and not feedback:
                print("\n✓ No issues found — great password!")

        print("\n" + "-" * 40)

if __name__ == "__main__":
    main()