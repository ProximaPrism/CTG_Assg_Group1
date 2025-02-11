# ECC Key Pair generator

import hashlib
import re
import sys
from tinyec import registry
from tinyec.ec import Curve, Point
import secrets
from colorama import Fore

# input validation
for i in [sys.argv[1], sys.argv[2], sys.argv[3]]:
    if len(i) == 0:
        print("One or more inputs was found to be missing")
        print("---------------------------------------")
        print(Fore.LIGHTCYAN_EX + "Valid curve types:")
        print(Fore.RESET + "--- NIST curves -----------")
        print("secp[192/224/256/384/521]r1")
        print("secp256k1")
        print()
        print("--- Brainpool curves --------------------")
        print("brainpoolP[160/192/224/256/320/384/512]r1")
        exit(1)

text: str = sys.argv[1]
row_key: int = int(sys.argv[2])
curve_type: str = sys.argv[3]

# -------------------------------------------------------------------
# rail fence cipher used as a diffusion layer

rail_fence = [["\n" for _ in range(len(text))] for _ in range(row_key)]

direction_below: bool = False
row, col = 0, 0

for i in range(len(text)):
    if (row == 0) or (row == row_key - 1):
        direction_below = not direction_below

    rail_fence[row][col] = text[i]
    col += 1

    if direction_below:
        row += 1
    else:
        row -= 1

ascii_code: list[str] = []
hash_str: str = ""
for i in range(row_key):
    for j in range(len(text)):
        if rail_fence[i][j] != "\n":
            ascii_code.append(str(ord(rail_fence[i][j])))
            hash_str.join(rail_fence[i][j])

# result is hashed using SHA256 and returned into the key generator
bit_size = [int(match) for match in re.findall(r"\d{3}", curve_type)]

# only going to be one match
hashed_result: int = int(hashlib.sha256(hash_str.encode()).hexdigest(), 16)

# -------------------------------------------------------------------
# ECC key pair generator based on chosen curve

curve: Curve = registry.get_curve(curve_type)
# generator point is influenced by rail fence hash and bit size inputs

gen_point: Point = curve.g * (hashed_result % secrets.randbits(bit_size[0]))

print(Fore.LIGHTCYAN_EX + f"\nCurve equation: ({curve_type})")
print(Fore.RESET, end="")
print(re.search(r"y\^2 = x\^3[^(]*", str(gen_point)).group(0))

print(Fore.LIGHTCYAN_EX + "\nField size (modulo divisor):")
print(Fore.RESET, end="")
print(
    re.search(r"\(mod [0-9]+\)", str(gen_point))
    .group(0)
    .strip("()")
    .removeprefix("mod ")
)

print(Fore.LIGHTCYAN_EX + "\nInitial coordinates:")
print(Fore.RESET, end="")

print(f"iX: {gen_point.x}")
print(f"iY: {gen_point.y}")

print(Fore.LIGHTRED_EX, "\nPrivate key:")
print(Fore.RESET, end="")

private_key = secrets.randbelow(curve.field.n - 1) + 1
print(f"d: {private_key}")

public_point: Point = private_key * gen_point

print(Fore.LIGHTBLUE_EX + "\nPublic coordinates:")
print(Fore.RESET, end="")
print(f"pX: {public_point.x}")
print(f"pY: {public_point.y}")
