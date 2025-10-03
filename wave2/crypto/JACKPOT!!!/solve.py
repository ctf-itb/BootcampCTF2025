#!/usr/bin/env python3
import pwn, math, re
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

LOCAL = False

def wait_menu_and_send(s, opt: int):
    s.recvuntil(b"Your move (1|2|3|4): ")
    s.sendline(str(opt).encode())

def get_int_after(s, marker: bytes):
    s.recvuntil(marker)
    return int(s.recvline().strip())

def ask_color(s, token: int) -> int:
    """
    Returns:
      0 -> 'red'   (even)
      1 -> 'black' (odd)
     -1 -> rejected (e.g., same as pot or not coprime)
    """
    wait_menu_and_send(s, 2)
    s.recvuntil(b"Slide a bet token (int): ")
    s.sendline(str(token).encode())
    line = s.recvline().decode(errors="ignore").strip()
    if line.startswith("Dealer whispers:"):
        return 0 if "red" in line else 1
    return -1

def try_extract_flag(m_int: int):
    b = long_to_bytes(m_int)
    if b'|' in b:
        return b.split(b'|', 1)[0]
    m = re.search(rb"CTFITB2025\{[^}]*\}", b)
    return m.group(0) if m else None

def main():
    if LOCAL:
        pty = pwn.process.PTY
        s = pwn.process(["python3", "chall.py"], stdin=pty, stdout=pty)
    else:
        s = pwn.remote("127.0.0.1", 8567)

    # read table info
    wait_menu_and_send(s, 1)
    n = get_int_after(s, b"table_limit = ")
    e = get_int_after(s, b"shuffle = ")
    pot = get_int_after(s, b"pot = ")

    two_e = pow(2, e, n)    # doubling under the public shuffle
    low, high = Fraction(0), Fraction(1)

    c = pot
    max_rounds = n.bit_length() + 4
    for _ in range(max_rounds):
        # multiply token by 2^e modulo table
        c = (c * two_e) % n

        # ask color (parity), retry a couple times if rejected
        res = -1
        for _r in range(3):
            res = ask_color(s, c)
            if res in (0, 1):
                break
        if res not in (0, 1):
            print("[!] Dealer rejected too often; folding.")
            s.close()
            return

        mid = (low + high) / 2
        if res == 0:
            # 'red' -> even -> no wrap -> m < mid*n
            high = mid
        else:
            # 'black' -> odd -> wrapped once -> m >= mid*n
            low = mid

        # stop when interval contains a single integer
        if (high - low) * n < 1:
            break

    # candidates from the final interval
    cand_hi = int(math.floor(high * n))
    cand_lo = int(math.ceil(low * n))
    cand_md = int(((low + high) / 2 * n).numerator // ((low + high) / 2 * n).denominator)

    for tag, m_int in [("hi", cand_hi), ("lo", cand_lo), ("mid", cand_md)]:
        flag = try_extract_flag(m_int)
        if flag:
            print(f"[+] FLAG: {flag.decode(errors='ignore')}")
            s.close()
            return

    print("[*] Couldn't auto-extract — inspect candidates manually.")
    s.close()

if __name__ == "__main__":
    main()
