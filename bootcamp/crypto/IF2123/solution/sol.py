#!/usr/bin/env sage -python

from sage.all import Matrix, ZZ, gcd, Integer, power_mod
import argparse, ast, re

def parse_output(path):
    with open(path, "r") as f:
        s = f.read()

    def find_int(key):
        m = re.search(rf"^{key}\s*=\s*([0-9]+)\s*$", s, re.M | re.I)
        if not m:
            raise ValueError(f"Key '{key}' not found in {path}")
        return int(m.group(1))

    def find_list(key):
        m = re.search(rf"^{key}\s*=\s*(\[[^\]]*\])\s*$", s, re.M | re.I | re.S)
        if not m:
            raise ValueError(f"Key '{key}' (list) not found in {path}")
        return [int(x) for x in ast.literal_eval(m.group(1))]

    N  = find_int("N")
    e  = find_int("e")
    ct = find_int("ct")
    mods = find_list("mods")
    return N, e, ct, mods

def int_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    bl = (x.bit_length() + 7) // 8
    return x.to_bytes(bl, "big")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="output.txt", help="Path to challenge output (default: output.txt)")
    args = ap.parse_args()

    n_int, e_int, ct_int, mods_int = parse_output(args.file)

    l = len(mods_int) + 1
    n = Integer(n_int)
    M = Matrix.identity(ZZ, l) * (-n)
    for i in range(1, l):
        M[0, i] = ZZ(mods_int[i-1])
    M[0, 0] = ZZ(1) << 400

    L = M.LLL()
    L00 = Integer(L[0, 0])
    g = gcd(abs(L00), n)

    print(f"L[0][0] = {L00}")
    print(f"gcd(L00, n) = {g}")

    p = Integer(g)
    q = n // p
    if p * q != n:
        p, q = q, p
        assert p * q == n

    phi = (p - 1) * (q - 1)
    e = Integer(e_int)
    ct = Integer(ct_int)

    d = pow(int(e), -1, int(phi))
    d = Integer(d)
    pt = Integer(power_mod(ct, d, n))
    m = int_to_bytes(int(pt))

    print("[+] p =", int(p))
    print("[+] q =", int(q))
    print("[+] flag:", repr(m))

if __name__ == "__main__":
    main()
