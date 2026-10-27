# F4 - XSS stocké (CWE-79)

Fichiers : `templates/posts.view.html:23` et `templates/messages.html:8`

```diff
- <span class="w3-h3">{{ post.text | safe }}</span>
+ <span class="w3-h3">{{ post.text }}</span>
```
Jinja2 échappe automatiquement les variables. Le filtre `| safe` désactive cette protection : un post contenant `<script>` s'exécute chez tous les lecteurs. Ajouter aussi un en-tête `Content-Security-Policy` strict en défense en profondeur.

# F5 / F6 - Configuration (CWE-489, CWE-798) : `vulpy.py:16` et `vulpy.py:55`

```diff
- app.config['SECRET_KEY'] = 'aaaaaaa'
+ app.config['SECRET_KEY'] = os.environ['SECRET_KEY']      # générée avec : python -c "import secrets; print(secrets.token_hex(32))"
- app.run(debug=True, host='127.0.1.1', port=5000, extra_files='csp.txt')
+ app.run(debug=False, host='127.0.0.1', port=5000)         # en production : gunicorn / waitress derrière un reverse proxy
```

# F7 - Clé d'API (CWE-338, CWE-22) : `libapi.py:14,16,20,33`

```diff
- key = hashlib.sha256(str(random.getrandbits(2048)).encode()).hexdigest()
+ key = secrets.token_urlsafe(32)
```
Stocker les clés (hachées) en base plutôt que dans des fichiers `/tmp` dont le nom contient le `username` saisi par l'utilisateur.

# F10 - Timeouts (CWE-400) : `api_list.py:10`, `api_post.py:16,30`

```diff
- requests.get(url, headers=headers)
+ requests.get(url, headers=headers, timeout=5)
```
