import sqlite3

conn = sqlite3.connect('secure_doc.db')

users = conn.execute(
    "SELECT username, user_id FROM users"
).fetchall()

for u in users:
    count = conn.execute(
        "SELECT COUNT(*) FROM honeysets WHERE user_id=?",
        (u[1],)
    ).fetchone()[0]

    print(f"User: {u[0]} → {count} honeywords in set")

conn.close()