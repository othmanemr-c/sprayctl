# Contribuer à sprayctl

Merci de l'intérêt porté au projet. Quelques règles avant d'ouvrir une PR.

## Setup dev

```bash
git clone https://github.com/ton-user/sprayctl.git
cd sprayctl
pip install -e ".[dev]" --break-system-packages
pytest tests/ -v
```

## Avant d'ouvrir une PR

- Les tests doivent passer (`pytest tests/`)
- Toute nouvelle fonctionnalité touchant à la logique de seuil/lockout
  (`orchestrator.py`) doit être accompagnée de tests — c'est le cœur
  critique de l'outil, une régression ici a un impact réel en mission
- Pas de secret, mot de passe, ou donnée de mission réelle dans le code ou
  les exemples
- Garde le style existant : dry-run par défaut, confirmation explicite
  avant toute action destructive/risquée, jamais de mot de passe loggé

## Signaler un bug

Ouvre une issue avec :
- Version de `sprayctl` (`sprayctl --version` si disponible, sinon commit hash)
- Commande exacte utilisée (**sans le mot de passe réel**, remplace par `***`)
- Comportement attendu vs observé

## Idées de contribution bienvenues

- Nouveaux connecteurs (Citrix, VPN, autres IdP)
- Amélioration du parsing de sortie NetExec (actuellement basé sur du texte,
  fragile aux changements de format)
- CI / tests d'intégration
