from sage.all import *
from Crypto.Util.number import long_to_bytes
import re

def parse(path="output.txt"):
    t = open(path).read()
    N = Integer(re.search(r"N\s*=\s*(\d+)", t).group(1))
    e = Integer(re.search(r"e\s*=\s*(\d+)", t).group(1))
    c = Integer(re.search(r"c\s*=\s*(\d+)", t).group(1))
    P = Integer(re.search(r"P\s*=\s*(\d+)", t).group(1))
    k = Integer(re.search(r"k\s*=\s*(\d+)", t).group(1))
    return N, e, c, P, k

def main():
    N, e, c, P, k = parse("output.txt")

    B = Integer(256)**k

    R.<x> = PolynomialRing(Zmod(N))
    f = (P*B + x)**e - c

    roots = f.small_roots(X=B, beta=1, epsilon=0.15)
    x0 = Integer(roots[0])
    m  = Integer(P)*B + x0
    print(long_to_bytes(int(m)))

if __name__ == "__main__":
    main()