"""
database.py — SQLite Database Layer for SecureDB Watch
Handles database initialization, table creation, dummy data seeding,
and safe query execution against the employees table.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")


def get_connection():
    """Create and return a new SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initialize the database:
    - Create the employees table if it doesn't exist.
    - Seed it with dummy data if the table is empty.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            salary REAL NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hire_date TEXT NOT NULL
        )
    """)

    # Only seed if the table is empty
    cursor.execute("SELECT COUNT(*) FROM employees")
    count = cursor.fetchone()[0]

    if count == 0:
        dummy_data = [
            ("Alice Johnson", "Engineering", 95000, "alice@securedb.io", "2022-01-15"),
            ("Bob Smith", "Marketing", 72000, "bob@securedb.io", "2021-06-20"),
            ("Charlie Brown", "Engineering", 105000, "charlie@securedb.io", "2020-03-10"),
            ("Diana Prince", "HR", 68000, "diana@securedb.io", "2023-02-01"),
            ("Ethan Hunt", "Security", 115000, "ethan@securedb.io", "2019-11-05"),
            ("Fiona Gallagher", "Finance", 82000, "fiona@securedb.io", "2021-09-14"),
            ("George Orwell", "Legal", 78000, "george@securedb.io", "2022-07-22"),
            ("Hannah Montana", "Marketing", 65000, "hannah@securedb.io", "2023-08-30"),
            ("Ivan Drago", "Security", 98000, "ivan@securedb.io", "2020-12-01"),
            ("Julia Roberts", "Engineering", 110000, "julia@securedb.io", "2019-05-18"),
        ]

        cursor.executemany(
            "INSERT INTO employees (name, department, salary, email, hire_date) VALUES (?, ?, ?, ?, ?)",
            dummy_data,
        )
        print("[DB] [OK] Seeded employees table with 10 records.")

    conn.commit()
    conn.close()
    print("[DB] [OK] Database initialized successfully.")


def execute_query(query):
    """
    Execute a SQL query against the database.

    Returns:
        dict with keys:
            - success (bool)
            - data (list[dict] | None) — for SELECT queries
            - rows_affected (int) — for INSERT/UPDATE/DELETE
            - message (str)
    """
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        query_stripped = query.strip().upper()

        if query_stripped.startswith("SELECT"):
            cursor.execute(query)
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description] if cursor.description else []
            data = [dict(zip(columns, row)) for row in rows]
            return {
                "success": True,
                "data": data,
                "rows_affected": len(data),
                "message": f"Query returned {len(data)} row(s).",
            }
        else:
            cursor.execute(query)
            conn.commit()
            rows_affected = cursor.rowcount
            return {
                "success": True,
                "data": None,
                "rows_affected": rows_affected,
                "message": f"Query executed successfully. {rows_affected} row(s) affected.",
            }

    except sqlite3.Error as e:
        return {
            "success": False,
            "data": None,
            "rows_affected": 0,
            "message": f"Database error: {str(e)}",
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "rows_affected": 0,
            "message": f"Unexpected error: {str(e)}",
        }
    finally:
        if conn:
            conn.close()


# Auto-init on import
if not os.path.exists(DB_PATH):
    init_db()
