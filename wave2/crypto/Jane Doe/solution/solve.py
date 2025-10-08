#!/usr/bin/env python3
import re
import ast
from extend_mt19937_predictor import ExtendMT19937Predictor

BACK_OFFSET = 63

def read(path="output.txt"):
    txt = open(path, "r", encoding="utf-8").read()

    def grab(name):
        m = re.search(rf"^{name}\s*=\s*(.+)$", txt, flags=re.M)
        if not m:
            raise ValueError(f"Missing {name} in {path}")
        return ast.literal_eval(m.group(1))

    b    = grab("b")
    p    = grab("p")
    enc  = grab("enc")
    hint = grab("hint")

    return b, p, enc, hint

def inv(a, m): 
    return pow(a, -1, m)

def derive(b, p, hint):
    Ms = []
    for i in range(len(hint) - 1):
        s_i   = hint[i]   % p
        s_ip1 = hint[i+1] % p
        Ms.append(((s_ip1 - b) * inv(s_i, p)) % p)
    return Ms

def solve(b, p, enc, hint):
    n = len(enc)
    Ms = derive(b, p, hint)

    pred = ExtendMT19937Predictor(check=True)
    for mval in Ms:
        pred.setrandbits(mval, 512)

    need_last_index = BACK_OFFSET + (n - 1)
    back = [pred.backtrack_getrandbits(512) for _ in range(need_last_index + 1)]
    m_prev = back[BACK_OFFSET : BACK_OFFSET + n]

    s_next = hint[0] % p
    seeds_rev = []
    for m_cur in m_prev:
        s_prev = ((s_next - b) * inv(m_cur % p, p)) % p
        seeds_rev.append(s_prev)
        s_next = s_prev
    seeds = list(reversed(seeds_rev))

    mask64 = (1 << 64) - 1
    blocks = []
    for i in range(n):
        val = (enc[i] ^ seeds[i]) & mask64
        blocks.append(val.to_bytes(8, "big"))
    return b"".join(blocks)

def main():
    b, p, enc, hint = read("output.txt")
    flag = solve(b, p, enc, hint)
    print("flag: ", flag)

if __name__ == "__main__":
    main()
