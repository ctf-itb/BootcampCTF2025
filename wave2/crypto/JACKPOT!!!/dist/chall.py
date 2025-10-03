#!/usr/bin/env python3
from Crypto.Util.number import getPrime, bytes_to_long, inverse
from secrets import token_bytes
from math import gcd
import sys

KEY_BITS = 2048
SHUFFLE = 0x10001
MAX_PEEKS = 4096

BANNER = r"""
┌──────────────────────────────────────────────────────────────┐
│ ♠ Poker Night: Parity Table                                  │
│ The Dealer shuffles and cuts.                                │
│ "Slide a bet token onto the felt, and I'll tell you a color: │
│   red (even) or black (odd) of what lies beneath."           │
└──────────────────────────────────────────────────────────────┘

Menu:
  1) Table info
  2) Place a bet
  3) Practice shuffle
  4) Cash out (leave)
"""

NOTE = b"CTFITB2025{fakeflagdontsubmit}"

class Dealer:
    def __init__(self, bits=KEY_BITS):
        while True:
            try:
                a, b = getPrime(bits // 2), getPrime(bits // 2)
                self.table_limit = a * b
                self.shuffle = SHUFFLE
                tally = (a - 1) * (b - 1)
                self._cut = inverse(self.shuffle, tally)
                break
            except ValueError:
                continue

    def mark(self, x: int) -> int:
        return pow(x, self.shuffle, self.table_limit)

    def lift(self, y: int) -> int:
        return pow(y, self._cut, self.table_limit)

def is_int(s: str) -> bool:
    try:
        int(s); return True
    except:
        return False

def main():
    dealer = Dealer(KEY_BITS)
    salt = token_bytes(16)

    note_val = bytes_to_long(NOTE + b"|" + salt)
    if note_val >= dealer.table_limit:
        print("House issue: note too large for this table.")
        sys.exit(1)

    pot = dealer.mark(note_val)
    peeks_left = MAX_PEEKS

    print(BANNER)

    while True:
        print(f"[peeks left: {peeks_left}]")
        choice = input("Your move (1|2|3|4): ").strip()

        if choice == "1":
            print("\n=== TABLE INFO ===")
            print("Open book of rules:")
            print(f"table_limit = {dealer.table_limit}")
            print(f"shuffle = {dealer.shuffle}")
            print(f"pot = {pot}\n")

        elif choice == "2":
            if peeks_left <= 0:
                print("Dealer taps the felt. 'No more color peeks tonight.'")
                continue

            s = input("Slide a bet token (int): ").strip()
            if not is_int(s):
                print("Dealer: 'Numbers only.'")
                continue

            token = int(s)
            if not (1 <= token < dealer.table_limit):
                print("Dealer: 'Bet within the table limits (1..table_limit-1)'.")
                continue

            if token == pot:
                print("Dealer chuckles: 'You can't peek the pot itself.'")
                continue

            if gcd(token, dealer.table_limit) != 1:
                print("Dealer nudges it back: 'No marked chips (must be coprime)'.")
                continue

            face = dealer.lift(token) & 1
            print(f"Dealer whispers: {'red' if face == 0 else 'black'}")
            peeks_left -= 1

        elif choice == "3":
            print("Practice shuffle: give the Dealer a note; get a token back.")
            msg = input("note (bytes hex or raw text): ").rstrip("\n")
            try:
                if (len(msg) >= 2 and
                    all(ch in "0123456789abcdefABCDEFx" for ch in msg)):
                    val = int(msg, 16)
                else:
                    val = bytes_to_long(msg.encode())
            except Exception:
                print("Dealer: 'Couldn't parse. Use hex or plain text.'")
                continue

            if not (0 <= val < dealer.table_limit):
                print("Dealer: 'Too big for the table. Shorten it.'")
                continue

            print(f"token = {dealer.mark(val)}")

        elif choice == "4":
            print("You rack your chips and step away from the felt.")
            break

        else:
            print("Dealer raps twice: 'Pick a valid option.'")

if __name__ == "__main__":
    main()
