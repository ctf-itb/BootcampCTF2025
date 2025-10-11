import argparse
import os
import re
import requests
import sqlite3
import time
from typing import Dict, List

RANK_WORD = {1: "First", 2: "Second", 3: "Third"}
MAX_RANK = 3

def escape_md(s: str) -> str:
    for ch in "\\*_`~|><#[](){}":
        s = s.replace(ch, "\\" + ch)
    return s

def format_announcement(rank_word: str, challenge: str, team: str) -> str:
    ch = escape_md(challenge)
    tm = escape_md(team)
    return f":knife::drop_of_blood: {rank_word} Blood! Challenge **{ch}** is blooded by **{tm}**! :cold_face:"

def log(msg: str) -> None:
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    print(f"{now}\t{msg}")


def setup_database(db_path: str) -> sqlite3.Connection:
    log(f"Connecting to sqlite3 db at '{db_path}'...")
    db = sqlite3.connect(db_path)
    db.execute(
        """CREATE TABLE IF NOT EXISTS announced_solves (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               challenge_id INTEGER,
               rank INTEGER,
               solver_id INTEGER,
               UNIQUE (challenge_id, rank)
           )"""
    )
    return db


def get_announced_ranks(db: sqlite3.Connection) -> Dict[int, int]:
    rows = db.execute(
        "SELECT challenge_id, MAX(rank) FROM announced_solves GROUP BY challenge_id"
    ).fetchall()
    return {cid: (mr if mr is not None else 0) for cid, mr in rows}


def get_challenges(session: requests.Session, solved_only: bool=False) -> List[dict]:
    res = session.get(f"{session.base_url}/api/v1/challenges", timeout=10)
    res.raise_for_status()
    challenges = res.json().get("data", [])
    if solved_only:
        challenges = [c for c in challenges if c.get("solves", 0) > 0]
    return challenges


def get_top_solves(session: requests.Session, challenge_id: int, limit: int = MAX_RANK) -> List[dict]:
    res = session.get(
        f"{session.base_url}/api/v1/challenges/{challenge_id}/solves",
        timeout=10
    )
    res.raise_for_status()
    data = res.json().get("data", [])

    data_sorted = sorted(data, key=lambda x: x.get("date", ""))
    return data_sorted[:limit]


def seed_existing(db: sqlite3.Connection, session: requests.Session) -> None:
    log("Seeding DB dengan first/second/third yang sudah ada...")
    solved_challs = get_challenges(session, solved_only=True)
    for ch in solved_challs:
        solves = get_top_solves(session, ch["id"], MAX_RANK)
        for idx, s in enumerate(solves, start=1):
            try:
                db.execute(
                    "INSERT OR IGNORE INTO announced_solves (challenge_id, rank, solver_id) VALUES (?, ?, ?)",
                    (ch["id"], idx, s.get("account_id"))
                )
            except sqlite3.Error as e:
                log(f"DB seed error for challenge {ch['id']}: {e}")
    db.commit()


def post_webhook(session: requests.Session, webhook: str, content: str) -> bool:
    try:
        res = session.post(webhook, json={"content": content}, timeout=10)

        if res.status_code == 429:
            retry = int(res.headers.get("Retry-After", "2"))
            log(f"Rate limited by Discord. Sleeping {retry}s")
            time.sleep(retry)
            res = session.post(webhook, json={"content": content}, timeout=10)
        if res.status_code in (200, 204):
            return True
        log(f"Webhook failed ({res.status_code}): {res.text}")
        return False
    except requests.RequestException as e:
        log(f"Webhook exception: {e}")
        return False


def announce_new_solves(db: sqlite3.Connection, session: requests.Session, webhook: str, announced_ranks: Dict[int, int]) -> None:
    solved_challenges = get_challenges(session, solved_only=True)

    for challenge in solved_challenges:
        cid = challenge["id"]
        name = challenge["name"]
        current_max = announced_ranks.get(cid, 0)

        solves = get_top_solves(session, cid, MAX_RANK)
        total_now = len(solves)
        if total_now <= current_max:
            continue

        for next_rank in range(current_max + 1, min(MAX_RANK, total_now) + 1):
            s = solves[next_rank - 1]
            team = s.get("name") or f"Account {s.get('account_id')}"
            msg = format_announcement(RANK_WORD[next_rank], name, team)

            log(f"Announcing {RANK_WORD[next_rank]} Blood for '{name}' by '{team}'")
            ok = post_webhook(session, webhook, msg)
            if ok:
                db.execute(
                    "INSERT OR IGNORE INTO announced_solves (challenge_id, rank, solver_id) VALUES (?, ?, ?)",
                    (cid, next_rank, s.get("account_id"))
                )
                db.commit()
                announced_ranks[cid] = next_rank


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="CTFd First/Second/Third Blood Announcer",
        description="Announce first three bloods from CTFd to Discord",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Tips:
- Gunakan --existing bila ingin MENGUMUMKAN juga blood yang sudah terjadi sebelum bot start.
- Kredensial bisa via argumen atau env: WEBHOOK_URL, CTFD_URL, CTFD_ACCESS_TOKEN, SITE_PASSWORD (opsional)."""
    )
    parser.add_argument("--webhook", help="Discord webhook URL")
    parser.add_argument("--ctfd", help="CTFd URL (contoh: https://ctf.example.org)")
    parser.add_argument("--token", help="CTFd access token")
    parser.add_argument("--existing", action="store_true", help="Umumkan yang sudah terjadi (history) saat start")
    parser.add_argument("--interval", type=int, default=5, help="Interval polling detik (default: %(default)s)")
    parser.add_argument("--db", default="solves.db", help="Path SQLite DB (default: %(default)s)")

    args = parser.parse_args()

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ModuleNotFoundError:
        pass

    args.webhook = args.webhook or os.getenv("WEBHOOK_URL")
    args.ctfd   = args.ctfd   or os.getenv("CTFD_URL")
    args.token  = args.token  or os.getenv("CTFD_ACCESS_TOKEN")
    site_password = os.getenv("SITE_PASSWORD")

    if args.webhook is None:
        raise parser.error("--webhook atau WEBHOOK_URL dibutuhkan")
    if args.ctfd is None:
        raise parser.error("--ctfd atau CTFD_URL dibutuhkan")
    if args.token is None:
        raise parser.error("--token atau CTFD_ACCESS_TOKEN dibutuhkan")

    if not re.match(r"^https?://discord.com/api/webhooks/", args.webhook):
        raise parser.error("Invalid Discord webhook URL")
    try:
        r_wh = requests.get(args.webhook, timeout=10)
        if r_wh.status_code not in (200, 204):
            raise parser.error("Discord webhook tidak bisa diakses")
    except requests.RequestException as e:
        raise parser.error(f"Gagal mengakses Discord webhook: {e}")

    if not re.match(r"^https?://", args.ctfd):
        raise parser.error("Invalid CTFd URL")
    try:
        r_ctfd_root = requests.get(args.ctfd, timeout=10)
        if r_ctfd_root.status_code >= 400:
            raise parser.error("CTFd URL tidak valid / tidak bisa diakses")
    except requests.RequestException as e:
        raise parser.error(f"Gagal mengakses CTFd URL: {e}")

    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/json",
        "Authorization": f"Token {args.token}",
    })
    if site_password:
        s.cookies.set("site_password", site_password)

    s.base_url = args.ctfd.rstrip("/")

    try:
        check = s.get(f"{s.base_url}/api/v1/challenges", timeout=10)
        if check.status_code != 200:
            raise parser.error("Unauthorized - invalid CTFd URL atau access token")
    except requests.RequestException as e:
        raise parser.error(f"Gagal akses CTFd API: {e}")

    args.session = s
    return args


def main():
    args = parse_args()

    log("Starting CTFd Discord First/Second/Third Blood Announcer...")
    db = setup_database(args.db)

    if not args.existing:
        seed_existing(db, args.session)
        announced_ranks = get_announced_ranks(db)
    else:
        log("Mode --existing: akan mengumumkan blood yang sudah ada saat start...")
        announced_ranks = get_announced_ranks(db)

    log("Bot running, waiting for bloods...")

    while True:
        try:
            log("Fetching new solves...")
            announce_new_solves(db, args.session, args.webhook, announced_ranks)
        except requests.exceptions.ConnectionError:
            log("Connection failed, retrying...")
        except requests.exceptions.Timeout:
            log("Request timed out, retrying...")
        except requests.RequestException as e:
            log(f"HTTP error: {e}")

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
