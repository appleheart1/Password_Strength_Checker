import hashlib
import requests

x = 'password'
byte_x = x.encode('utf-8')
hash_x = hashlib.sha1(byte_x)
hex_out = hash_x.hexdigest()
print (hex_out)

first_5 = hex_out[0:5]
first_5 = first_5.upper()
print (first_5)

full_url = 'https://api.pwnedpasswords.com/range/' + first_5
api_return = requests.get(full_url)
api_split = api_return.text.split('\n')

for i in api_split:
    if i.split(':')[0] == hex_out[5:].upper():
        sides = i.split(':')
        count = sides[1]
        print (count)