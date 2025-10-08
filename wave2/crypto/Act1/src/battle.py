#!/usr/bin/env python3
from Crypto.Util.number import getPrime, bytes_to_long, inverse
from secrets import token_bytes
from math import gcd
import sys

KEY_BITS = 2048
SHUFFLE = 0x10001
MAX_PEEKS = 4096

BANNER = r"""
┌────────────────────────────────────────────────────────────────────────────┐
│ A small café after hours. Reze laughs easily, Denji grins like the hero    │
│ he wishes he were. The rain becomes their soundtrack.                      │
│                                                                            │
│ They wander an aquarium that feels like forever: the same tank again, and  │
│ again, until someone finally breaks the loop. On the school rooftop the    │
│ chain snarls, the fuse hisses. In the pool below, a fight is also a kind   │
│ of confession. A kiss turns into a live grenade.                           │
│                                                                            │
│ Tonight, you stand in that narrow space between them—color is all you get. │
│                                                                            │
│ FIELD RULES                                                                │
│ • A sealed core lies between them, a shard of truth only one can carry.    │
│ • Cast integer sigils; the world answers with a single color:              │
│        red  → even                                                         │
│        black → odd                                                         │
│ • Do not offer the sealed core itself. Some lines are not crossed.         │
│                                                                            │
│ Fireworks bloom over the city. Choices hurt. Read the colors.              │
└────────────────────────────────────────────────────────────────────────────┘

Menu:
  1) Field intel
  2) Cast a sigil
  3) Sparring drill
  4) Walk away
"""

NOTE = b"CTFITB2025{c4n_y0u_st1ll_3xpl0d3_wh3n_y0u_4r3_w3t?????????}"

class Arbiter:
    def __init__(self, bits=KEY_BITS):
        while True:
            try:
                p, q = getPrime(bits // 2), getPrime(bits // 2)
                self.N = p * q
                self.e = SHUFFLE
                phi = (p - 1) * (q - 1)
                self._d = inverse(self.e, phi)
                break
            except ValueError:
                continue

    def tear(self, x: int) -> int:
        return pow(x, self.e, self.N)

    def suture(self, y: int) -> int:
        return pow(y, self._d, self.N)

def is_int(s: str) -> bool:
    try:
        int(s); return True
    except:
        return False

def main():
    arb = Arbiter(KEY_BITS)
    salt = token_bytes(16)

    note_val = bytes_to_long(NOTE + b"|" + salt)
    if note_val >= arb.N:
        print("The air snaps: that truth is too large for this night.")
        sys.exit(1)

    C = arb.tear(note_val)
    peeks_left = MAX_PEEKS

    print(BANNER)

    while True:
        print(f"[peeks left: {peeks_left}]")

        choice = input("Your move (1|2|3|4): ").strip()

        if choice == "1":
            print("\n=== FIELD INTEL ===")
            print("You steady your breath and take stock:")

            print(f"veil = {arb.N}")
            print(f"rift = {arb.e}")
            print(f"core = {C}\n")

        elif choice == "2":
            if peeks_left <= 0:
                print("Reze wipes rain from her lashes. 'No more whispers tonight.'")
                continue

            s = input("Offer a sigil (int): ").strip()
            if not is_int(s):
                print("Narrator: 'Numbers only.'")
                continue

            token = int(s)
            if not (1 <= token < arb.N):
                print("Narrator: 'Stay within the bounds (1..veil-1)'.")
                continue

            if token == C:
                print("Denji: 'Not the sealed core.'")
                continue

            if gcd(token, arb.N) != 1:
                print("Narrator: 'No cursed sigils (must be coprime with veil)'.")
                continue

            face = arb.suture(token) & 1

            if face == 0:
                print("Reze whispers: red")
            else:
                print("Reze whispers: black")
            peeks_left -= 1

        elif choice == "3":
            print("Sparring drill: write a note; feel how the night pushes back.")
            msg = input("note (bytes hex or raw text): ").rstrip("\n")
            try:
                if (len(msg) >= 2 and
                    all(ch in '0123456789abcdefABCDEFx' for ch in msg)):
                    val = int(msg, 16)
                else:
                    val = bytes_to_long(msg.encode())
            except Exception:
                print("Narrator: 'Couldn't parse. Use hex or plain text.'")
                continue

            if not (0 <= val < arb.N):
                print("Narrator: 'Too large for this veil. Shorten it.'")
                continue

            print(f"token = {arb.tear(val)}")

        elif choice == "4":
            print("Chains wind down. The fuse fades. You walk into the rain.")
            break

        else:
            print("Footsteps circle. 'Pick a valid option.'")

if __name__ == "__main__":
    main()
