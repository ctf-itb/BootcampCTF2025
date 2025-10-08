#!/usr/bin/env python3
import pwn, math, re
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

LOCAL = False
HOST = "127.0.0.1"
PORT = 8567

WHISPER_RE = re.compile(r"\bwhispers:\s*(red|black)\b", re.I)

def wait_menu_and_send(s, opt: int):
    s.recvuntil(b"Your move (1|2|3|4): ")
    s.sendline(str(opt).encode())

def get_int_after(s, marker: bytes):
    s.recvuntil(marker)
    return int(s.recvline().strip())

def ask_color(s, token: int) -> int:
    """
    Returns:
      0 -> red   (even)
      1 -> black (odd)
     -1 -> rejected
    """
    wait_menu_and_send(s, 2)
    s.recvuntil(b"Offer a sigil (int): ")
    s.sendline(str(token).encode())

    line = s.recvline().decode(errors="ignore").strip()
    m = WHISPER_RE.search(line)
    if m:
        return 0 if m.group(1).lower() == "red" else 1
    return -1

def try_extract_flag(m_int: int):
    b = long_to_bytes(m_int)
    if b'|' in b:
        return b.split(b'|', 1)[0]
    m = re.search(rb"CTFITB2025\{[^}]*\}", b)
    return m.group(0) if m else None

def main():
    if LOCAL:
        p = pwn.process(["python3", "src/battle.py"])
    else:
        p = pwn.remote(HOST, PORT)

    # 1) Field intel
    wait_menu_and_send(p, 1)
    N = get_int_after(p, b"veil = ")
    e = get_int_after(p, b"rift = ")
    C = get_int_after(p, b"core = ")

    two_e = pow(2, e, N)
    low, high = Fraction(0), Fraction(1)

    c = C
    max_rounds = N.bit_length() + 4
    for _ in range(max_rounds):
        c = (c * two_e) % N

        res = -1
        for _r in range(3):
            res = ask_color(p, c)
            if res in (0, 1):
                break
        if res not in (0, 1):
            print("[!] Rejected too often; aborting.")
            p.close()
            return

        mid = (low + high) / 2
        if res == 0:
            high = mid
        else:
            low = mid

        if (high - low) * N < 1:
            break

    cand_hi = int(math.floor(high * N))
    cand_lo = int(math.ceil(low * N))
    cand_md = int(((low + high) / 2 * N).numerator // ((low + high) / 2 * N).denominator)

    for tag, m_int in [("hi", cand_hi), ("lo", cand_lo), ("mid", cand_md)]:
        flag = try_extract_flag(m_int)
        if flag:
            print(f"[+] FLAG: {flag.decode(errors='ignore')}")
            p.close()
            return

    print("[*] Candidates did not parse; inspect manually.")
    p.close()

if __name__ == "__main__":
    main()
