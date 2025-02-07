# ECC Key Pair generator

import hashlib
import re
import sys
from tinyec import registry
import secrets
from colorama import Fore

text = sys.argv[1]

# input validation

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

# -------------------------------------------------------------------
# Rail fence cipher used as a diffusion layer

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

# -------------------------------------------------------------------
# ECC key pair generator based on chosen curve

curve_type = sys.argv[3]

curve = registry.get_curve(curve_type)
point = secrets.randbelow(curve.field.n) * curve.g

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
private_key = (hashed_result ^ exponent) % secrets.randbelow(curve.field.n)
print(f"d: {private_key}")

public_point = private_key * point

print(Fore.LIGHTBLUE_EX + "\nPublic coordinates:")
print(Fore.RESET, end="")
print(f"pX: {public_point.x}")
print(f"pY: {public_point.y}")
