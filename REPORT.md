# Rapport de revue de code sécurisé : Vulpy (version `bad/`)

## 1. Périmètre et méthode

| Élément | Détail |
|---|---|
| Application | Vulpy, Flask, SQLite, 495 lignes de code Python |
| Outil statique | Bandit : 22 alertes (2 High, 14 Medium, 6 Low), voir `reports/` |
| Revue manuelle | `libuser.py`, `libsession.py`, `libapi.py`, `mod_user.py`, `mod_posts.py`, `vulpy.py`, templates |
| Référentiels | OWASP Top 10 (2021), CWE |
| Limite | Bandit ne voit ni le XSS dans les templates, ni la session forgeable, ni les mots de passe en clair : ces constats viennent de la revue manuelle. |

## 2. Synthèse

| ID | Constat | Gravité | CWE | Source |
|---|---|---|---|---|
| F1 | Injection SQL | Élevée | CWE-89 | Bandit + manuel |
| F2 | Mots de passe stockés en clair | Élevée | CWE-256 | Manuel |
| F3 | Session forgeable (cookie base64 non signé) | Élevée | CWE-565 | Manuel |
| F4 | XSS stocké (`\| safe`) | Élevée | CWE-79 | Manuel |
| F5 | Flask `debug=True` | Élevée | CWE-489 / CWE-94 | Bandit (High) |
| F6 | `SECRET_KEY` codée en dur (`aaaaaaa`) | Élevée | CWE-798 | Bandit (Low) + manuel |
| F7 | Clés d'API faibles, stockées dans `/tmp` | Moyenne | CWE-338 / CWE-377 / CWE-22 | Bandit + manuel |
| F8 | Cookie de session sans `HttpOnly`, `Secure`, `SameSite` | Moyenne | CWE-1004 / CWE-614 | Manuel |
| F9 | Pas de limite de tentatives ni de politique de mot de passe | Moyenne | CWE-307 / CWE-521 | Manuel |
| F10 | Requêtes `requests` sans timeout | Faible | CWE-400 | Bandit |
| F11 | `try/except/pass` qui masque les erreurs | Faible | CWE-703 | Bandit |
| F12 | Les requêtes SQL, mots de passe compris, sont écrites dans les logs | Moyenne | CWE-532 | Manuel |

## 3. Constats détaillés

### F1 : Injection SQL (CWE-89, OWASP A03)
- **Où** : `libuser.py:12` (login), `:25` (create), `:53` (password_change) ; aussi `db.py:19`, `db_init.py:20`
- **Code** : `"SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)`
- **Impact** : contournement de l'authentification (`admin' --` comme nom d'utilisateur), lecture et modification de la base.
- **Correctif** : requêtes paramétrées (`WHERE username = ?`), voir `fixes/01_sql_injection.py`. Le fichier `libposts.py` de la même application le fait déjà correctement, ce qui montre que la bonne pratique est connue mais appliquée de façon incohérente.
- **Preuve** : _à compléter (capture de la connexion avec `admin' --`)_

### F2 : Mots de passe en clair (CWE-256, OWASP A02)
- **Où** : `libuser.py:25` (stockage), `:12` (comparaison directe)
- **Impact** : une fuite de la base (ou F1) expose tous les mots de passe, réutilisés ailleurs par beaucoup d'utilisateurs.
- **Correctif** : scrypt, bcrypt ou argon2 avec sel aléatoire et comparaison à temps constant, voir `fixes/02_password_hashing.py`.

### F3 : Session forgeable (CWE-565 / CWE-345, OWASP A07)
- **Où** : `libsession.py:6-7` (création), `:15-19` (lecture)
- **Code** : `base64.b64encode(json.dumps({'username': username}))`
- **Impact** : n'importe qui fabrique le cookie `{"username":"admin"}` et usurpe un compte sans mot de passe.
- **Correctif** : cookie signé et expirant (`itsdangerous`), voir `fixes/03_signed_session.py`.
- **Preuve** : _à compléter (cookie `vulpy_session` forgé avec `echo -n '{"username":"admin"}' \| base64`)_

### F4 : XSS stocké (CWE-79, OWASP A03)
- **Où** : `templates/posts.view.html:23`, `templates/messages.html:8` (`{{ post.text | safe }}`)
- **Impact** : un post contenant du JavaScript s'exécute dans le navigateur de chaque lecteur : vol de cookie (aggravé par F8), actions au nom de la victime.
- **Correctif** : retirer `| safe` et laisser Jinja2 échapper, ajouter une CSP, voir `fixes/04_xss_and_config.md`.
- **Preuve** : _à compléter (publier un post `<script>alert(1)</script>`)_

### F5 : Mode debug actif (CWE-489 / CWE-94, OWASP A05)
- **Où** : `vulpy.py:55` (`app.run(debug=True, ...)`), signalé High par Bandit (B201)
- **Impact** : le débogueur Werkzeug permet l'exécution de code à distance s'il est exposé.
- **Correctif** : `debug=False`, serveur WSGI en production.

### F6 : Clé secrète codée en dur (CWE-798, OWASP A02)
- **Où** : `vulpy.py:16` (`SECRET_KEY = 'aaaaaaa'`), Bandit B105
- **Impact** : clé triviale et publique dans le dépôt, donc forgeable. Note : la version `good/` de l'auteur garde aussi une clé en dur, une amélioration qui reste insuffisante.
- **Correctif** : lire la clé depuis une variable d'environnement.

### F7 : Clés d'API faibles (CWE-338 / CWE-377 / CWE-22)
- **Où** : `libapi.py:14` (`random.getrandbits`, non cryptographique), `:16,20,33` (fichiers dans `/tmp` dont le nom contient le `username`)
- **Impact** : clés potentiellement prévisibles ; un `username` contenant des séparateurs de chemin pourrait influencer le chemin du fichier (_à confirmer par un test_).
- **Correctif** : `secrets.token_urlsafe(32)`, stockage haché en base.

### F8 : Cookie sans attributs de sécurité (CWE-1004 / CWE-614)
- **Où** : `libsession.py:7` (`set_cookie` sans options)
- **Correctif** : `httponly=True, secure=True, samesite="Lax"`, voir `fixes/03_signed_session.py`.

### F9 : Pas de protection contre la force brute (CWE-307 / CWE-521, OWASP A07)
- **Où** : `mod_user.py:9-35` (aucune limite), `libuser.py` (`password_complexity` retourne toujours `True`)
- **Impact** : le script `brute.py` fourni avec l'application le démontre.
- **Correctif** : limitation de débit, verrouillage temporaire, règles de complexité, MFA obligatoire.

### F10 : Requêtes sans timeout (CWE-400)
- **Où** : `api_list.py:10`, `api_post.py:16,30` (Bandit B113)
- **Correctif** : `timeout=5`.

### F11 : Exceptions avalées (CWE-703)
- **Où** : `libsession.py:21` (`except Exception: pass`, Bandit B110)
- **Correctif** : intercepter l'erreur précise et la journaliser.

### F12 : Journalisation de données sensibles (CWE-532, OWASP A09)
- **Où** : `libuser.py:8` et fichiers voisins (`conn.set_trace_callback(print)`)
- **Impact** : chaque requête, avec le mot de passe qu'elle contient, est affichée dans la console et les logs.
- **Correctif** : supprimer le traçage ou ne journaliser aucune donnée d'authentification.

## 4. Recommandations générales

1. Imposer les requêtes paramétrées partout (règle de revue de code + analyse Bandit/Semgrep dans la CI).
2. Ne jamais construire soi-même l'authentification et les sessions : utiliser des bibliothèques éprouvées (Flask-Login, Authlib).
3. Garder l'échappement automatique des templates actif, `| safe` seulement sur du contenu assaini.
4. Séparer configuration et code : secrets en variables d'environnement, `debug=False` hors développement.
5. Ajouter des tests de sécurité (injection, XSS, session) et un `pip-audit` sur les dépendances.

## 5. Limites

L'analyse porte sur la version `bad/` et sur une lecture de code : elle ne prétend pas être exhaustive. Les preuves marquées « à compléter » doivent être réalisées en local avant publication.
