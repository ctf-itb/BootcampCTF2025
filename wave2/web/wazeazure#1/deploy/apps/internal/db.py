import os
from pg8000.native import Connection


def get_conn():
    return Connection(
        user=os.getenv("DB_USER", "dreamhack"),
        password=os.getenv("DB_PASSWORD", "[SECRET]"),
        host=os.getenv("DB_HOST", "db"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=os.getenv("DB_NAME", "dreamhack"),
    )
