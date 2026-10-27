# CodeAlpha_SecureCodingReview

Revue de code sécurisé réalisée dans le cadre du stage Cyber Security CodeAlpha (Tâche 3).

- **Langage** : Python (Flask)
- **Application auditée** : [Vulpy](https://github.com/fportantier/vulpy), application web volontairement vulnérable, dossier `bad/` (495 lignes de code)
- **Méthodes** : analyse statique avec Bandit, revue manuelle selon l'OWASP Top 10, validation locale des failles principales
- **Résultat** : 12 constats (voir [REPORT.md](REPORT.md)), dont 6 de gravité élevée

## Contenu du dépôt

| Élément | Rôle |
|---|---|
| `REPORT.md` | Constats détaillés : localisation, gravité, CWE, impact, correctif |
| `reports/` | Sorties brutes de Bandit (txt, json, html) |
| `fixes/` | Correctifs sous forme de code exécutable (`python3 fixes/01_sql_injection.py`) |
| `screenshots/` | Preuves de validation des failles |
| `run_audit.sh` | Reproduit l'analyse statique de bout en bout |

## Reproduire l'analyse

```bash
./run_audit.sh
```
Le script clone Vulpy, installe Bandit et Semgrep dans un environnement virtuel et écrit les rapports dans `reports/`.

## Avertissement

Vulpy est conçue pour s'entraîner. Les tests d'exploitation ont été faits uniquement en local, sur ma propre instance. N'attaquez jamais un système sans autorisation.
