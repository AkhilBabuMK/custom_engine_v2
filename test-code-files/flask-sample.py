from flask import request
import sqlite3

def vulnerable():
    user_input = request.args.get('q')  # Source
    conn = sqlite3.connect('db.sqlite')
    
    # Should trigger SQLI-001
    conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    
    # Should trigger XSS-001
    return f"<div>{user_input}</div>"

# Add vulnerable code patterns
def another_vulnerability():
    raw_data = request.form['data']
    cur = sqlite3.connect('log.db').cursor()
    cur.executemany(f"INSERT INTO logs VALUES ({raw_data})")
    return f"<script>alert('{raw_data}')</script>"