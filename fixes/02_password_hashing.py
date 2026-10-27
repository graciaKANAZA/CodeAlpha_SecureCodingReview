"""F2 - Mots de passe en clair (CWE-256 / CWE-916). Fichier d'origine : bad/libuser.py (create, login)."""
import hashlib, hmac, os

# AVANT : INSERT ... VALUES ('%s', '%s', ...) % (username, password)  -> mot de passe stocké tel quel
# APRES : dérivation scrypt avec sel aléatoire, comparaison à temps constant
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + dk.hex()

def verify_password(password: str, stored: str) -> bool:
    salt_hex, dk_hex = stored.split("$")
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    return hmac.compare_digest(dk.hex(), dk_hex)

if __name__ == "__main__":
    h = hash_password("S3cret!")
    print("bon mot de passe :", verify_password("S3cret!", h))
    print("mauvais mot de passe :", verify_password("autre", h))
