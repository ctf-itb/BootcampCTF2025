import os
import re
from pathlib import Path
from functools import lru_cache
from typing import List

import pymysql
from flask import Flask, request, render_template

app = Flask(__name__, template_folder="templates")

# config
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["DEBUG"] = False
app.config["TESTING"] = False
app.config["TEMPLATES_AUTO_RELOAD"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "False") == "True"

DB_HOST = os.environ.get("DB_HOST", "db")
DB_USER = os.environ.get("DB_USER", "ballon_user")
DB_PASS = os.environ.get("DB_PASS", "ballon_pass")
DB_NAME = os.environ.get("DB_NAME", "ballon")

INDEX_HTML = "index.html"
RESULTS_HTML = "results.html"
KEYWORDS_FILE = Path(__file__).parent.joinpath("sql_keywords.txt")


@lru_cache(maxsize=1)
def _load_keywords(path: Path = KEYWORDS_FILE) -> List[str]:
    words: List[str] = []
    if not path.exists():
        return words
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            words.append(line)
    return words


def _clean_quotes(value: str) -> str:
    if value is None:
        return ""
    return re.sub(r"['\"]", "", value)


def _clean_chars(value: str) -> str:
    pattern = r"[0-9\s\t\-\;\{\}]"
    return re.sub(pattern, "", value, flags=re.IGNORECASE)


def _clean_keywords(value: str, words: List[str]) -> str:
    if not words:
        return value
    escaped = [re.escape(w) for w in words if w.strip()]
    if not escaped:
        return value
    pattern = "|".join(escaped)
    return re.sub(pattern, "", value, flags=re.IGNORECASE)


def sanitize_input(v: str) -> str:
    if v is None:
        return ""
    v = _clean_quotes(v)
    v = _clean_chars(v)
    v = _clean_keywords(v, _load_keywords())
    return v


def get_conn():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


@app.route("/")
def index():
    return render_template(INDEX_HTML)


@app.route("/search")
def search():
    param_a_raw = request.args.get("name", "")
    param_b_raw = request.args.get("club", "")

    param_a_sanitized = sanitize_input(param_a_raw)
    param_b_sanitized = sanitize_input(param_b_raw)

    exec_query = f"SELECT name, year, club FROM players WHERE name = '{param_a_sanitized}' AND club = '{param_b_sanitized} '"
    
    print("[Executing] :", exec_query, flush=True)

    rows = []
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(exec_query)
            rows = cur.fetchall()
    except Exception as e:
        # keep output minimal in web UI; log to container stdout for operator
        rows = []
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return render_template(RESULTS_HTML,
                           exec_query=exec_query,
                           rows=rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
