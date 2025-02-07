# CTG_Assg_Group1
### A repository to store files for CTG Assignment
Obvious warning that implementations of these files should NOT be used in prod

## Before running the programs
### Make sure you have pip installed and the following packages
- hashlib
- re
- sys
- colorama
- secrets
- tinyec

### If you do not have any of these packages, run:
`pip install <package_name>`

## File descriptions / documentation
### railfenceECCkeygen
#### Generates a public-private key pair with help from the tinyec library
```python
import hashlib
import re
import sys
from tinyec import registry
import secrets
from colorama import Fore

text = sys.argv[1]

try:
    empty = sys.argv[1][0] == ""
    if empty:
        raise IndexError("No valid message was found")
except IndexError:
    print("No valid message was found")
    exit(1)

try:
    empty = sys.argv[2][0] == ""
    if empty:
        raise IndexError("No rail fence key input was found")
except IndexError:
    print("No rail fence cipher key input was found")
    exit(1)

try:
    empty = sys.argv[3][0] == ""
    if empty:
        raise IndexError("No valid ECC curve type input was found")
except IndexError:
    print("No valid ECC curve type input was found")
    print("---------------------------------------")
    print(Fore.LIGHTCYAN_EX + "Valid curve types:")
    print(Fore.RESET + "--- NIST curves -----------")
    print("secp[192/224/256/384/521]r1")
    print("secp256k1")
    print()
    print("--- Brainpool curves --------------------")
    print("brainpoolP[160/192/224/256/320/384/512]r1")
    exit(1)

row_key = int(sys.argv[2])
rail = [["\n" for i in range(len(text))] for j in range(row_key)]

direction_below = False
row, col = 0, 0

for i in range(len(text)):
    if (row == 0) or (row == row_key - 1):
        direction_below = not direction_below

    rail[row][col] = text[i]
    col += 1

    if direction_below:
        row += 1
    else:
        row -= 1

exponent = []
hash = ""
for i in range(row_key):
    for j in range(len(text)):
        if rail[i][j] != "\n":
            exponent.append(str(ord(rail[i][j])))
            hash.join(rail[i][j])

# result is hashed using SHA256 and returned into the key generator
# exponent is reversed and converted to an integer for key generation
exponent = int("".join(exponent[::-1]))
hashed_result = int(hashlib.sha256(hash.encode()).hexdigest(), 16)

curve_type = sys.argv[3]

curve = registry.get_curve(curve_type)
point = secrets.randbelow(curve.field.n) * curve.g
print(curve.g)

print(Fore.LIGHTCYAN_EX + f"\nCurve equation: ({curve_type})")
print(Fore.RESET, end="")
print(re.search(r"y\^2 = x\^3[^(]*", str(point)).group(0))

print(Fore.LIGHTCYAN_EX + "\nField size (modulo divisor):")
print(Fore.RESET, end="")
print(
    re.search(r"\(mod [0-9]+\)", str(point)).group(0).strip("()").removeprefix("mod ")
)

print(Fore.LIGHTCYAN_EX + "\nInitial coordinates:")
print(Fore.RESET, end="")

print(f"iX: {point.x}")
print(f"iY: {point.y}")

print(Fore.LIGHTRED_EX, "\nPrivate key:")
print(Fore.RESET, end="")
private_key = hashed_result % secrets.randbelow(curve.field.n)
print(f"d: {private_key}")

public_point = private_key * point

print(Fore.LIGHTBLUE_EX + "\nPublic coordinates:")
print(Fore.RESET, end="")
print(f"pX: {public_point.x}")
print(f"pY: {public_point.y}")
```
- Rail fence is used as a diffusion layer, creating an exponent, `e` and a hash, `h` from SHA256 
- Hash `h` is passed into the key generator (ECC) to be used in the private key / public key points
- An initial point, `(iX, iY)` is created based on a random integer less than n (private curve multiplier), `n` multiplied by the generator point for the curve, `g`
- The private key multiplier, `d` is created from: `h^e (mod n)`
- Public key points `(pX, pY)` are generated from: `(iX, iY) * d`
