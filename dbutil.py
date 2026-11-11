"""Small schema-tolerant SQLite helpers used by the Person 4 modules.

The Person 4 code must work against the repository's existing tables without
knowing every column up-front, so inserts/updates only touch columns that exist
and NOT NULL columns without default get a neutral filler.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Sequence

__all__ = ["fetch_all", "fetch_one", "has_table", "columns", "has_column", "insert_row", "update_row"]


def fetch_all(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    cur = conn.execute(sql, tuple(params))
    names = [d[0] for d in cur.description or []]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def fetch_one(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
    rows = fetch_all(conn, sql, params)
    return rows[0] if rows else None


def has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def columns(conn: sqlite3.Connection, table: str) -> Dict[str, Dict[str, Any]]:
    out = {}
    for cid, name, typ, notnull, dflt, pk in conn.execute(f'PRAGMA table_info("{table}")').fetchall():
        out[name] = {"type": (typ or "").upper(), "notnull": bool(notnull), "default": dflt, "pk": bool(pk)}
    return out


def has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return column in columns(conn, table)


def insert_row(conn: sqlite3.Connection, table: str, values: Dict[str, Any]) -> int:
    cols = columns(conn, table)
    row = {k: v for k, v in values.items() if k in cols}
    for name, meta in cols.items():
        if name in row or meta["pk"] or not meta["notnull"] or meta["default"] is not None:
            continue
        row[name] = 0 if ("INT" in meta["type"] or "REAL" in meta["type"] or "NUM" in meta["type"]) else ""
    names = ", ".join(f'"{c}"' for c in row)
    marks = ", ".join("?" for _ in row)
    cur = conn.execute(f'INSERT INTO "{table}" ({names}) VALUES ({marks})', tuple(row.values()))
    return int(cur.lastrowid or 0)


def update_row(conn: sqlite3.Connection, table: str, where_col: str, where_val: Any, values: Dict[str, Any]) -> int:
    cols = columns(conn, table)
    row = {k: v for k, v in values.items() if k in cols}
    if not row:
        return 0
    sets = ", ".join(f'"{c}"=?' for c in row)
    cur = conn.execute(f'UPDATE "{table}" SET {sets} WHERE "{where_col}"=?', (*row.values(), where_val))
    return cur.rowcount
