from __future__ import annotations
import re, ast, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from binascii import unhexlify
from sage.all import ZZ, Matrix, vector, PolynomialRing, Ideal, diagonal_matrix
from sage.modules.free_module_integer import IntegerLattice


def parse_out_file():
    with open("out.txt", "r", encoding="utf-8") as f:
        text = f.read()

    mR   = re.search(r'^\s*R\s*=\s*(\[.*?\])\s*$', text, re.S | re.M)
    mV   = re.search(r'^\s*values\s*=\s*(\[.*?\])\s*$', text, re.S | re.M)
    mIV  = re.search(r'^\s*iv\s*=\s*(.+?)\s*$', text, re.S | re.M)
    mENC = re.search(r'^\s*enc\s*=\s*(.+?)\s*$', text, re.S | re.M)

    if not (mR and mV and mIV and mENC):
        raise ValueError("Gagal parsing: pastikan out.txt berisi R=..., values=..., iv=..., enc=...")

    R = ast.literal_eval(mR.group(1))
    values = ast.literal_eval(mV.group(1))

    iv_raw  = mIV.group(1).strip()
    enc_raw = mENC.group(1).strip()

    iv  = ast.literal_eval(iv_raw)  if (iv_raw[:1]  in "'\"") else iv_raw
    enc = ast.literal_eval(enc_raw) if (enc_raw[:1] in "'\"") else enc_raw
    return R, values, iv, enc

# From rbtree's LLL repository
# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat: Matrix, target):
    M = IntegerLattice(mat, lll_reduce=True).reduced_basis
    G = M.gram_schmidt()[0]
    diff = target
    for i in reversed(range(G.nrows())):
        diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
    return target - diff

def solve_cvp(M: Matrix, lbounds, ubounds, weight=None):
    mat = Matrix(M)
    lb  = list(lbounds)
    ub  = list(ubounds)
    num_var  = mat.nrows()
    num_ineq = mat.ncols()

    max_element = 0
    for i in range(num_var):
        for j in range(num_ineq):
            max_element = max(max_element, abs(mat[i, j]))

    if weight is None:
        weight = num_ineq * max_element if max_element else 1

    if len(lb) != num_ineq or len(ub) != num_ineq:
        raise ValueError("len(lb) or len(ub) != num_ineq")

    for i in range(num_ineq):
        if lb[i] > ub[i]:
            raise ValueError(f"lb[{i}] > ub[{i}]")

    max_diff = max([ub[i] - lb[i] for i in range(num_ineq)]) if num_ineq else 1
    applied_weights = []

    for i in range(num_ineq):
        span = ub[i] - lb[i]
        ineq_weight = weight if span == 0 else (max_diff // span if span else weight)
        ineq_weight = int(ineq_weight) if ineq_weight else 1
        applied_weights.append(ineq_weight)
        for j in range(num_var):
            mat[j, i] *= ineq_weight
        lb[i] *= ineq_weight
        ub[i] *= ineq_weight

    target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
    result = Babai_CVP(mat, target)

    fin = None

    if num_var == num_ineq:
        try:
            fin = mat.transpose().solve_right(result)
        except Exception:
            fin = None
    return result, applied_weights, fin


def coeff_matrix_from_polys(polys):
    mon = []
    idx = {}
    rows = []

    for p in polys:
        ms = p.monomials()
        cs = p.coefficients()
        if len(ms) != len(cs):
            d = p.dict()
            ms = list(d.keys())
            cs = [d[m] for m in ms]
        rows.append((cs, ms))
        for m in ms:
            if m not in idx:
                idx[m] = len(mon)
                mon.append(m)

    B = [[0] * len(mon) for _ in range(len(polys))]
    for r, (cs, ms) in enumerate(rows):
        for c, m in zip(cs, ms):
            B[r][idx[m]] = ZZ(c)

    return Matrix(ZZ, B), mon

def safe_ZZ(a):
    try:
        if hasattr(a, "is_integer") and not a.is_integer():
            return None
        return ZZ(a)
    except Exception:
        return None

def run_attack(R, values, iv_hex, enc_hex):
    N_bitlen = 1024
    fix = 4

    def generate_lambda(vals):
        Lscale = ZZ(2) ** 2000
        block = len(vals)
        Mat = [[0 for _ in range(block + 1)] for _ in range(block)]
        for i in range(block):
            Mat[i][0] = ZZ(vals[i]) * Lscale
            Mat[i][i + 1] = 1

        Mat = Matrix(ZZ, Mat)
        Mx = ZZ(2) ** (N_bitlen // (len(vals) - 2) + 10)
        Lb = [0] + [-Mx] * (len(vals) - 1) + [1]
        Ub = [0] + [ Mx] * (len(vals) - 1) + [1]

        sol, w, _ = solve_cvp(Mat, Lb, Ub)
        truesol = []
        for (a, b) in zip(sol, w):
            truesol.append(a // b)
        vec = truesol[1:]
        vec = vector(ZZ, vec)
        assert vec[-1] == 1
        vec *= -1
        return vec

    Rng = PolynomialRing(ZZ, 'y', len(values) + 2)
    gens = list(Rng.gens())
    y = gens[:len(values)]
    n, d = gens[-2], gens[-1]

    # polyY: y[0..fix-1] literal; rest are y0..y_{fix-1}
    polyY = [y[i] for i in range(fix)]
    for i in range(fix, len(values)):
        vec = generate_lambda(values[:fix] + [values[i]])
        pol = Rng(0)
        for j in range(fix):
            pol += vec[j] * y[j]
        pol += y[i]
        polyY.append(pol)

    good = [Rng(1)]
    for a in range(fix, len(values)):
        good.append(y[a])
        good.append(y[a] * n)

    def Genseq(subst_idx):
        eqs = []
        for i in list(range(fix)) + list(subst_idx):
            pol = ZZ(values[i]) * d - 1 - polyY[i] * (n + ZZ(R[i]))
            eqs.append(pol)

        Bmat, mon = coeff_matrix_from_polys(eqs)

        W = []
        for Mn in mon:
            if Mn not in good:
                W.append(ZZ(2) ** 3000)
            else:
                W.append(1 if Mn == 1 else ZZ(2) ** 2000)

        Wmat = diagonal_matrix(W)
        BW = (Bmat * Wmat).LLL()

        pls = []
        for v0 in BW[:max(1, len(values) - fix - 1)]:
            unweighted = []
            ok = True
            for a, w in zip(v0, W):
                q = a / w
                qi = safe_ZZ(q)
                if qi is None:
                    ok = False
                    break
                unweighted.append(qi)
            if not ok:
                continue

            pl = Rng(0)
            Mx = 0
            Wok = True
            for (a, b) in zip(unweighted, mon):
                if b not in good:
                    Wok = False
                if b.degree() != 2:
                    pl += a * b
                Mx = max(Mx, int(a).bit_length())
            if Wok:
                pls.append(pl)

            pl2 = Rng(0)
            Wok2 = True
            for a, b in zip(unweighted, mon):
                if b not in good and a != 0:
                    Wok2 = False
                if b.degree() == 2:
                    assert (b % n) == 0
                    pl2 += a * Rng(b / n)
            if Wok2 and Mx < (2 * N_bitlen) // fix:
                pls.append(pl2)

        return pls

    seq = Genseq([i for i in range(fix, len(values))])

    I = list(seq)
    for i in range(len(values)):
        pol = ZZ(values[i]) * d - 1 - polyY[i] * (n + ZZ(R[i]))
        I.append(pol)

    gb = Ideal(I).groebner_basis()

    # d: a*d + b = 0
    coef_d = None
    coef_const = None
    for poly in reversed(gb):
        ms = poly.monomials()
        cs = poly.coefficients()

        if len(ms) != len(cs):
            dct = poly.dict()
            ms = list(dct.keys())
            cs = [dct[m] for m in ms]

        cd, c0 = None, None
        for c, m in zip(cs, ms):
            if m == 1:
                c0 = ZZ(c)
            elif m == d:
                cd = ZZ(c)
        if cd is not None:
            coef_d, coef_const = cd, c0
            break

    if coef_d is None:
        raise RuntimeError("Failed to find linear equation in d from Gröbner basis.")

    if coef_d == 0:
        raise RuntimeError("Coefficient d = 0 in linear equation.")

    ans_d = -coef_const // coef_d if coef_const is not None else ZZ(0)


    # Dec
    key = hashlib.sha256(str(int(ans_d)).encode()).digest()
    iv  = unhexlify(iv_hex)
    enc = unhexlify(enc_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(enc), 16)
    return pt

def main():
    R, values, iv, enc = parse_out_file()
    flag = run_attack(R, values, iv, enc)
    try:
        print(flag.decode())
    except:
        print(flag)

if __name__ == "__main__":
    main()
