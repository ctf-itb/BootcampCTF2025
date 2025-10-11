from Crypto.Util.number import getStrongPrime, bytes_to_long

e = 3
k = 5

flag = b"CTFITB2025{I_looped_this_song_while_making_this_chall_https://youtu.be/sakOV_IkB4o?si=EtPZK5H8V2p_BaYV}" # fake flag, don't submit

def gen():
    p = getStrongPrime(1024)
    q = getStrongPrime(1024)
    N = p * q

    head = flag[:-k]
    tail   = flag[-k:]

    P = bytes_to_long(head)
    x = int.from_bytes(tail, 'big')
    B = pow(256, k)

    m = P * B + x
    c = pow(m, e, N)

    return N, e, c, P, k

if __name__ == "__main__":
    N, e, c, P, k = gen()
    with open("output.txt", "w") as f:
        f.write(f"N = {N}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")
        f.write(f"P = {P}\n")
        f.write(f"k = {k}\n")
