"""F3 + F8 - Session forgeable et cookie sans flags (CWE-565 / CWE-1004). Fichier d'origine : bad/libsession.py."""
from itsdangerous import URLSafeTimedSerializer, BadSignature   # installé avec Flask

# AVANT : cookie = base64(json({'username': ...})) -> n'importe qui peut fabriquer {"username": "admin"}
# APRES : cookie signé (et expirant) avec une clé secrète
SECRET = "remplacer-par-os.environ['SECRET_KEY']"
s = URLSafeTimedSerializer(SECRET)

def create(response, username):
    response.set_cookie("session", s.dumps({"username": username}),
                        httponly=True, secure=True, samesite="Lax", max_age=7200)
    return response

def load(request):
    try:
        return s.loads(request.cookies.get("session", ""), max_age=7200)
    except BadSignature:          # signature invalide ou expirée : session vide
        return {}

if __name__ == "__main__":
    token = s.dumps({"username": "alice"})
    print("cookie valide accepté :", s.loads(token))
    try:
        s.loads("eyJ1c2VybmFtZSI6ImFkbWluIn0")   # base64 de {"username":"admin"} forgé à la main
    except BadSignature:
        print("cookie forgé refusé")
