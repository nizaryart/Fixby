import sqlite3

LIST_QUERY = "SELECT * FROM findings WHERE (:status IS NULL OR status = :status)"


def unsafe(conn: sqlite3.Connection, name, table, ids):
    # ruleid: sql-built-from-runtime-string
    conn.execute(f"SELECT * FROM findings WHERE title = '{name}'")
    # ruleid: sql-built-from-runtime-string
    conn.execute("SELECT * FROM %s" % table)
    # ruleid: sql-built-from-runtime-string
    conn.execute("SELECT * FROM {}".format(table))
    # ruleid: sql-built-from-runtime-string
    conn.execute("SELECT * FROM findings WHERE title = '" + name + "'")
    query = f"DELETE FROM findings WHERE id IN ({ids})"
    # ruleid: sql-built-from-runtime-string
    conn.executescript(query)


def safe(conn: sqlite3.Connection, name, finding):
    # ok: sql-built-from-runtime-string
    conn.execute("SELECT * FROM findings WHERE title = ?", (name,))
    # ok: sql-built-from-runtime-string
    conn.execute(LIST_QUERY, {"status": None})
    # ok: sql-built-from-runtime-string
    conn.execute(
        "INSERT INTO findings (title, product)"
        " VALUES (:title, :product)",
        finding,
    )
    query = "SELECT 1"
    # ok: sql-built-from-runtime-string
    conn.execute(query)
