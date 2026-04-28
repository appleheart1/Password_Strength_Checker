import re
from datetime import date
import hashlib
import requests
import math

def password_rules(password):
    """
    Set rules for password and appropriate feedback

    Checks the password against six scoring rules and awards points for length, uppercase,
    lowercase digits, special characters and feedback (suggestions).

    Returns score 0-8 and feedback String.
    """

    score = 0
    feedback = []

    #length rules
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append('Use at least 8 character (12+ is best)')

    #Case rules
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append('Add at least one uppercase letter (A-Z)')
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append('Add at least one lowercase letter (a-z)')

    #number rule
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append('Add at least one number character (0-9)')

    #special character rule
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 2
    else:
        feedback.append('Add at least one special character ([!@#$%^&*(),.?":{}|<>])')

    #repeated char/num rule
    if re.search(r'(.)\1{2,}', password):
        score -=1
        feedback.append('Avoid repeating characters (e.g. aaa or 111)')
    elif len (password) >=8:
        score += 1

    #no negative score
    score = max(score, 0)
    return score, feedback

def calc_true_entropy(password):
    """
    Calculates the true entropy of a password in bits.

    Entropy measures how unpredictable/random a password is, the higher the bits the harder
    it is to crack. Takes into account both length and variety of characters used.

    Pool is the total number of possible characters the attacker has to guess from. For example
    if your password only uses lowercase letters the pool is 26, but if it also uses digits the
    pool grows to 36, making each harder to guess.

    This function returns the entropy value in bits rounded to 7 decimal places as a float.
    """

    if not password:
        return 0
    pool = 0
    if any(c.islower() for c in password):
        pool+= 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum () for c in password):
        pool += 20

    # Entropy formula: E = L x log2(P)
    # L = password  length, P = character pool size
    E = len(password) * math.log2(pool)

    return round(E, 7)

def calc_time_to_crack(password):
    """
    Calculates the time a modern computer would take to crack with entropy.

    Converts into human-readable format (years, days and hours).The function returns the time
    to crack in a human-readable format such as '24,745 years' or 'Billions of years (practically uncrackable)'.
    """

    entropy = calc_true_entropy(password)
    total_combinations = 2**entropy
    # guesses_per_second is 100,000,000,000 as is estimation based on modern GPU Tech
    guesses_per_second = 100_000_000_000
    # seconds_to_crack is divided by two as attackers often find password halfway through not at end
    seconds_to_crack = total_combinations/ (2*guesses_per_second)
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

def does_contain_common(password):
    """
    Compares password to a list of 10 thousand most common passwords

    Uses the file '10k-most-common.txt' to compare to passed in password and returns any
    matches that it finds regardless of case. Returns True if found or False if not (or file missing).
    """

    try:
        with open("10k-most-common.txt", 'r') as f:
            common_pswd = f.read().split('\n')
            for i in common_pswd:
                if i.strip() == password.lower():
                    return True
            return False
    #Returns false instead of Error as if the file is missing it would crash the program so instead just skip.
    except FileNotFoundError:
        return False

def password_score_strength(score):
    """
    Converts a numerical score to human-readable strength label.

    Maps score ranges to labels:
    0-1 = Very Weak, 2-3 = Weak, 4-5 = Fair, 6 = Strong, 7+ = Very Strong.

    Returns a string label representing the password strength.
    """

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

def birthday_format_handle(birthday):
    """
    Processes user input into 'dd', 'mm', 'yyyy' chunks for later comparison.

    Input form that are accepted are 'ddmmyyyy' or 'dd/mm/yyyy' either splitting by '/'
    or assuming that the input will be split after position 2 and 4 if the user enters an
    unexpected format it will ask instead for an age to work off of.

    Returns a list of birthday variations as strings which contains all bite-sized parts to be compared
    in PI detection.
    """

    variations = [birthday]

    #process '/' split such as 24/2/2004
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
        #Numerous variations/combinations as attackers try many common formats
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
    # Removes duplicates from list so score remains correct and less clustered feedback
    variations = list(dict.fromkeys(variations))
    #Filter out empty strings as they could cause false matches in PI detection
    return [v for v in variations if v]

def common_pattern_in_password(password):
    """
    Identifies if commonly used phrases are used in any part of the password.

    Checks against list 'sequence' and adds any matches to 'matches' list.

    Returns a Tuple (True, list of matches) if found  or (False, empty list)
    if no matches.
    """

    #Very common phrases and keyboard sequences attacks try in dictionary attacks
    sequence = ['qwerty', 'qwert', 'werty', 'asdfg', 'asdfgh',
                'zxcvbnm', 'qwertyuiop', 'vbnhb', 'tress', 'drews', '123'
                ,'12345', '123456', '23456', '2345', '234',]
    matches = []
    for i in sequence:
        if i in password.lower():
            matches.append(i)
    if matches:
        return True, matches

    return False, []

def pi_in_passwords(password, personal_info):
    """
    Checks if personal info appears in the password.

    Creates a list for potential matches then iterates through items in personal info and
    compares if matches appear they are appended to 'matches' list. Only adds matches once
    to ensure no duplicates.

    Returns Tuple (True, list of matches) if found  or (False, empty list).
    """

    matches = []
    for info in personal_info:
        #Only checks for string containing 2 or more characters otherwise unuseful matches are made
        if info and len(info) >= 2 and info in password.lower():
            # Only appends if not in list already
            if info not in matches:
                matches.append(info)
    if matches:
        return True, matches
    return False, []

def calculate_age(birthday):
    """
    Calculates age based on birthday.

    From the format 'ddmmyyyy' or 'dd/mm/yyyy' age is calculated and returns none if entered
    birthday format is not correct

    Returns age as int

    """
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

    # Checks if birthday has occurred yet this year and if not takes one off age
    if (today.month, today.day) < (dob.month, dob.day):
        age -= 1

    return age

def leet_speak_conversion(password):
    """
    Converts leet speak substitutions in a password back to standard characters.

    Leet speak replaces letters with visually similar characters (e.g. 3=e).
    Attackers use these substitutes to bypass simple common password checks

    Returns a Tuple (converted string, list of substituted pairs found, bool if converted
    result is a common password).
    """

    leet_dict = {'4':'a', '@':'a', '^':'a', 'I3':'b', '{':'c', '[)':'d', '3':'e',
                '£':'e', '€':'e', 'ph':'f', '9':'g', '#':'h', '1':'i', '!':'i', ']':'j'
                , '|(':'k', '|_':'l', '/V':'n', '0':'o', 'Ø':'o', '|^':'p',
                '0_':'q', 'I2':'r', '$':'s', "']['":'t','|_|':'u', 'µ':'u',
                 'vv':'w', '><':'x', ')(':'x', '7':'y', '2':'z', '7_':'z'
                }
    converted = ""
    i = 0
    leet_pairs = []
    #Detects already detected substitutions and avoid duplicate warnings
    seen = set()

    #Manual while loop instead of for due to two character substitutions need to skip by 2
    while i < len(password):
        two_char = password[i:i+2].lower()
        one_char = password[i].lower()

        #Checks two char before one as substitutions like ph=f before matching single characters
        if two_char in leet_dict:
            replacement = leet_dict[two_char]
            converted += replacement
            if two_char not in seen:
                leet_pairs.append((two_char, replacement))
                seen.add(two_char)
            i += 2
        elif one_char in leet_dict:
            replacement = leet_dict[one_char]
            converted += replacement
            if one_char not in seen:
                leet_pairs.append((one_char,replacement))
                seen.add(one_char)
            i += 1
        else:
            converted += one_char
            i += 1
    #Only mark if the converted version is a common password
    is_leet_common = does_contain_common(converted)

    return converted, leet_pairs, is_leet_common

def have_i_been_pwned(password):
    """
    Checks against known password breaches via 'https://api.pwnedpasswords.com/range/'

    Uses K-anonymity : Only sends 5 characters of the SHA-1 are sent to API (meaning the
    full password never leaves the device)

    The API returns all hashes starting with those 5 characters which are then compared
    further locally to find full matching hex string then appends number of times breached.

    Returns (number of breaches, 0 if clean, None if no internet connection)
    """

    #password -> bytes -> hashed -> hex
    bytes_pswd = password.encode('utf-8')
    hashed_pswd = hashlib.sha1(bytes_pswd)
    hex_out = hashed_pswd.hexdigest()

    # take first 5 of hashed to pass to api (no full passwords leave program)
    first_5 = hex_out[0:5]
    first_5 = first_5.upper()
    try:
        #pass first 5 characters in hash to compare to leaked at url
        full_url = 'https://api.pwnedpasswords.com/range/' + first_5
        #get returned list of matching prefix and split by return
        api_return = requests.get(full_url)
        api_split = api_return.text.split('\n')
    except requests.exceptions.RequestException:
        print("\n[!] WARNING: Please check your internet connection,\nconnection couldn't be made so couldn't check if \npassword is breached against You've Been Pwned database")
        return None

    # compare affix to returned and find count of breach if any
    for i in api_split:
        if i.split(':')[0] == hex_out[5:].upper():
            sides = i.split(':')
            count = sides[1]
            return int(count)

    return 0

def main():
    #Sets up formatted header for readability
    print("=" * 40)
    print("    Password Strength Checker")
    print("=" * 40)

    #Taking user input and assigning to relevant variables
    full_name = input("\nPlease enter your First and last name (first last)\n:").lower()
    name_parts = full_name.split()
    birthday = input("\nPlease enter your birthdate (DD/MM/YYYY or DDMMYYYY)\n:")

    #Building personal info and formatting for processing
    birthday_variations = birthday_format_handle(birthday)

    age = calculate_age(birthday)
    if age is not None:
        age_str = str(age)

    else:
        age_str = input("\nCould not calculate age — please enter it manually\n:").lower()

    personal_info = name_parts + [age_str] + birthday_variations
    personal_info = list(dict.fromkeys(personal_info))

    #Main loop: repeatedly checks password until user quits
    while True:
        password = input('\nPlease Enter a password to check (or Q/q to quit)\n:')

        if not password.strip():
            print('\nNo password entered. Please try again. (or Q/q to quit)')
            continue

        if password.lower() == 'q':
            print ("\nGoodbye!")
            break

        #Checks with have I been Pwned database (without password leaving device)
        count = have_i_been_pwned(password)

        if count is not None and count > 0:
            print(f"\n[!] WARNING: Your password was found in {count} data breaches!" )
            print(f"    Please choose a new password.")

        else:

            #Checks if password is common
            if does_contain_common(password):
                print("\n[!] WARNING: This is one of the most common passwords ever used.")
                print("    It would be cracked instantly.")

            # If passes common password and HIBP check
            else:
                #calls necessary functions and assigns returned values to variables to print later if present
                keyboard_found, keyboard_matched = common_pattern_in_password(password)
                leet_password, leet_pairs, is_leet_common = leet_speak_conversion(password)
                found, matched = pi_in_passwords(password, personal_info)
                leet_found, leet_matched = pi_in_passwords(leet_password, personal_info)
                leet_matched = [item for item in leet_matched if item not in matched]
                leet_found = len(leet_matched) > 0
                score, feedback = password_rules(password)
                score_deduct = 0

                # Total Score calculations
                for _ in matched:
                    score_deduct -= 1
                pi_score_deduct = score_deduct

                for _ in leet_matched:
                    score_deduct -= 1
                leet_score_deduct = score_deduct - pi_score_deduct

                if len(keyboard_matched) == 1:
                    score_deduct -= 1
                elif len(keyboard_matched) > 1:
                    score_deduct -= 2

                score += score_deduct
                score =(max(score, 0))



                label = password_score_strength(score)
                time_to_crack = calc_time_to_crack(password)
                entropy = calc_true_entropy(password)

                #Output based of off analysis
                print(f"\nStrength     : {label}")
                print(f"Score        : {score}/8")
                print(f"Entropy is = {entropy}")
                print(f"Time to crack: {time_to_crack}")

                if count == 0:
                    print("\nNot Found in any data breaches")

                if found:
                    print(f"\n[!] WARNING: Your password contains personal information:")
                    print(f"    Found: '{"','".join(matched)}'", pi_score_deduct, "point/s" )
                    print(f"    Attackers try names, birthdays and ages first!")

                if leet_found:
                    print(f"\n[!] WARNING: Your password contains leet speak personal information:")
                    print(f"    Found: '{"','".join(leet_matched)}'", leet_score_deduct, "point/s")
                    print(f"    Attackers try names, birthdays and ages first!")

                if feedback:
                    print("\nSuggestions:")
                    for tip in feedback:
                        print(f"  -> {tip}")
                if keyboard_found:
                    print(f"\n[!] WARNING: Your password contains a common sequence:")
                    print(f"    Found: {', '.join(keyboard_matched)}")
                    print(f"    Attackers try common sequences first")

                if is_leet_common and leet_pairs:
                    print(f"\n[!] WARNING: Your password contains a common leet speak/substitution:")
                    formatted = [f"{orig} = {conv}" for orig, conv in leet_pairs]
                    print(f"    Found: {', ' .join(formatted)}")
                    print(f"    Attackers use leet substitutions to guess your password")

                if not found and not feedback and not keyboard_found and not leet_found:
                    print("\n✓ No issues found — great password!")

        print("\n" + "-" * 40)

if __name__ == "__main__":
    main()