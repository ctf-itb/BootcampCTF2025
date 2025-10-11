from pwn import process, remote, context
from pathlib import Path
from typing import Dict, List, Tuple
import argparse, re

context.log_level = "error"

def bitcount(x: int) -> int:
    return sum(int(b) for b in bin(x)[2:])

def last_int_token(line: bytes) -> int:
    return int(line.decode().strip().split()[-1])

def recvline_text(tube, timeout=5.0) -> str:
    data = tube.recvline(timeout=timeout)
    if not data:
        raise RuntimeError("Timeout waiting for a line from target.")
    return data.decode(errors="replace").strip()

def build_strategy(batch: int = 5, e_list: List[int] = [1, 2, 4]) -> List[Dict[Tuple[int, ...], List[int]]]:
    strat: List[Dict[Tuple[int, ...], List[int]]] = []
    base = pow(8, batch)
    for E in e_list:
        D: Dict[Tuple[int, ...], List[int]] = {}
        for i in range(base):
            U = bitcount(i + base * E)
            L = []
            for j in range(1, pow(2, batch)):
                V = bitcount(i - pow(j, 3) + base * E)
                L.append((U - V) % 2)
            key = tuple(L)
            D.setdefault(key, []).append(i)
        strat.append(D)
    return strat

SIG_PAT = re.compile(r"The truth is:\s*([0-9]+)")

def start_process_target(target_path: str):
    resolved = Path(__file__).parent.joinpath(target_path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Target not found: {resolved}")
    return process(["python3", str(resolved)])

def start_remote_target(host: str, port: int):
    return remote(host, port)

def read_signature(io, max_skip: int = 10) -> int:
    skipped = []
    for _ in range(max_skip):
        line = recvline_text(io)
        m = SIG_PAT.search(line)
        if m:
            return int(m.group(1))
        skipped.append(line)
    raise RuntimeError("Failed to parse signature line. Saw:\n" + "\n".join(skipped))

def oracle_query(io, x: int) -> int:
    _ = recvline_text(io)
    io.sendline(str(x).encode())
    line = recvline_text(io)
    return int(line)

def oracle_guess(io, guess_val: int) -> str:
    _ = recvline_text(io)
    io.sendline(b"guess")
    io.sendline(str(guess_val).encode())
    return io.recvall(timeout=5.0).decode(errors="replace")

def infer_bits_and_build_modulus(io, strat: List[Dict[Tuple[int, ...], List[int]]], batch: int = 5, LM: int = 1024) -> int:
    Ncount = (oracle_query(io, -1) + 1) % 2

    U: List[object] = ['?'] * LM
    U[-1] = 1  # MSB

    def derive_pattern(idx_div3: int) -> Tuple[int, ...]:
        L = []
        for j in range(1, pow(2, batch)):
            L.append((Ncount - oracle_query(io, -pow(2, (idx_div3 - batch)) * j)) % 2)
        return tuple(L)

    for i in range(LM - 1, -1, -3):
        # E = 1
        if U[i] == 1 and i // 3 >= batch:
            L = derive_pattern(i // 3)
            nums = list(strat[0][L])
            bits = []
            for _ in range(batch * 3):
                has = 0
                for k in range(len(nums)):
                    has |= (1 << (nums[k] % 2))
                    nums[k] //= 2
                if   has == 1: bits.append(0)
                elif has == 2: bits.append(1)
                else:          bits.append("?")
            t = 0
            for k in range(3 * (i // 3 - batch), 3 * (i // 3)):
                if bits[t] != "?":
                    U[k] = bits[t]
                t += 1

        # E = 2
        if i + 1 < len(U) and U[i + 1] == 1 and U[i] == 0 and i // 3 >= batch:
            L = derive_pattern(i // 3)
            nums = list(strat[1][L])
            bits = []
            for _ in range(batch * 3):
                has = 0
                for k in range(len(nums)):
                    has |= (1 << (nums[k] % 2))
                    nums[k] //= 2
                if   has == 1: bits.append(0)
                elif has == 2: bits.append(1)
                else:          bits.append("?")
            t = 0
            for k in range(3 * (i // 3 - batch), 3 * (i // 3)):
                if bits[t] != "?":
                    U[k] = bits[t]
                t += 1

        # E = 4
        if i + 2 < len(U) and U[i + 2] == 1 and U[i + 1] == 0 and U[i] == 0 and i // 3 >= batch:
            L = derive_pattern(i // 3)
            nums = list(strat[2][L])
            bits = []
            for _ in range(batch * 3):
                has = 0
                for k in range(len(nums)):
                    has |= (1 << (nums[k] % 2))
                    nums[k] //= 2
                if   has == 1: bits.append(0)
                elif has == 2: bits.append(1)
                else:          bits.append("?")
            t = 0
            for k in range(3 * (i // 3 - batch), 3 * (i // 3)):
                if bits[t] != "?":
                    U[k] = bits[t]
                t += 1

    ans = 0
    for idx, b in enumerate(U):
        if b == 1:
            ans |= (1 << idx)
    return ans

def run_process_mode(target: str, batch: int, LM: int) -> None:
    strat = build_strategy(batch=batch, e_list=[1, 2, 4])
    io = start_process_target(target)
    try:
        sig = read_signature(io)
        n_recovered = infer_bits_and_build_modulus(io, strat=strat, batch=batch, LM=LM)
        candidate_secret = pow(sig, 3, n_recovered)
        out = oracle_guess(io, candidate_secret)
        print(out, end="")
    finally:
        io.close()

def run_remote_mode(host: str, port: int, batch: int, LM: int) -> None:
    strat = build_strategy(batch=batch, e_list=[1, 2, 4])
    io = start_remote_target(host, port)
    try:
        sig = read_signature(io)
        n_recovered = infer_bits_and_build_modulus(io, strat=strat, batch=batch, LM=LM)
        candidate_secret = pow(sig, 3, n_recovered)
        out = oracle_guess(io, candidate_secret)
        print(out, end="")
    finally:
        io.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["process", "remote"], default="process",
                    help="process: run local script; remote: connect to host:port")
    ap.add_argument("--target", default="../src/battle.py",
                    help="Path to battle.py (used in process mode).")
    ap.add_argument("--host", default="127.0.0.1", help="Remote host (remote mode).")
    ap.add_argument("--port", type=int, default=8567, help="Remote port (remote mode).")
    ap.add_argument("--batch", type=int, default=5)
    ap.add_argument("--LM", type=int, default=1024)
    args = ap.parse_args()

    if args.mode == "process":
        run_process_mode(args.target, args.batch, args.LM)
    else:
        run_remote_mode(args.host, args.port, args.batch, args.LM)
