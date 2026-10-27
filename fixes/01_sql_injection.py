"""F1 - Injection SQL (CWE-89). Fichier d'origine : bad/libuser.py (login, create, password_change)."""
import sqlite3

# AVANT (vulnérable) : la saisie est insérée dans la requête
#   c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password))
# Avec username = admin' --  le mot de passe n'est plus vérifié.

# APRES : requête paramétrée, la saisie reste une donnée
def get_user(conn, username):
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

if __name__ == "__main__":
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES ('admin', 'x')")
    print("injection neutralisée :", get_user(conn, "admin' --") is None)
