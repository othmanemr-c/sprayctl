# sprayctl


> ⚠️ **Usage strictement réservé aux tests d'intrusion autorisés par écrit.**
> Utiliser cet outil contre un système sans autorisation explicite du
> propriétaire est illégal dans la plupart des juridictions.

Orchestrateur de password spray **lockout-aware** pour pentest interne et externe.

## Le problème que ça résout

Le password spraying est l'une des attaques les plus rentables en pentest, mais
aussi l'une des plus risquées : chaque annuaire a une politique de lockout
différente, souvent inconnue au départ. Sprayer à l'aveugle avec un script
maison ou un outil brut, c'est prendre le risque de **verrouiller des comptes
réels chez le client** — un incident business, pas juste un problème technique.

Multiplier les cibles (AD interne, O365, VPN, Citrix...) veut dire gérer
plusieurs politiques de lockout en parallèle, généralement à la main dans un
tableur — source classique d'erreur humaine en mission.

`sprayctl` centralise cette gestion : il découvre la vraie politique de
lockout avant de commencer, respecte un seuil de sécurité avec marge, et
s'arrête automatiquement dès qu'un verrouillage est détecté — même si la
politique estimée était fausse.

## Comment ça marche

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│  1. DISCOVERY     │ ──▶ │  2. ORCHESTRATEUR     │ ──▶ │  3. CONNECTEURS       │
│  (Module 1/1bis)  │     │  (Module 2/3)         │     │  (Module 4)           │
│                    │     │                        │     │                       │
│ Lit ou mesure la   │     │ État SQLite par        │     │ SMB/LDAP/WinRM/RDP/   │
│ vraie politique    │     │ (user, service).       │     │ SSH via NetExec, ou   │
│ de lockout AD      │     │ Calcule le rythme      │     │ O365/Entra ID via     │
│ (LDAP ou test      │     │ sûr (marge 80% par     │     │ OAuth ROPC            │
│ contrôlé)          │     │ défaut) + jitter.      │     │                       │
└─────────────────┘     └──────────────────────┘     └─────────────────────┘
                                     │
                                     ▼
                          ┌──────────────────────┐
                          │  4. AUDIT LOG (JSONL)  │
                          │  Traçabilité contrac-  │
                          │  tuelle : chaque essai,│
                          │  horodaté, sans jamais │
                          │  écrire de mot de passe│
                          └──────────────────────┘
```

Le principe central : **`sprayctl` ne garantit jamais l'absence de lockout**,
il réduit fortement le risque en respectant une politique de lockout réelle
(mesurée, pas devinée) avec une marge de sécurité, et il s'arrête net au
premier signe de verrouillage plutôt que de continuer à l'aveugle.

## Structure du projet

```
sprayctl/
├── pyproject.toml            → packaging pip, point d'entrée console
├── README.md
├── .gitignore                 → exclut DB de campagne, mots de passe, users de mission
├── sprayctl/
│   ├── cli.py                   → point d'entrée, 4 sous-commandes
│   ├── discovery.py              → Module 1 : lecture LDAP directe de la policy
│   ├── empirical_discovery.py    → Module 1bis : mesure par test contrôlé (LDAP fermé)
│   ├── orchestrator.py            → Module 2/3 : état SQLite + rythme + jitter
│   ├── audit_log.py                → Module 5 : traçabilité JSON pour le rapport de mission
│   ├── display.py                   → sortie terminal colorée (ANSI)
│   └── connectors/
│       ├── netexec.py                → SMB/LDAP/WinRM/RDP/SSH via NetExec
│       └── o365.py                    → O365/Entra ID via OAuth ROPC
└── tests/                              → 68 tests unitaires (pytest)
```

## Installation

```bash
tar -xzf sprayctl.tar.gz && cd sprayctl

# Installation utilisateur (commande `sprayctl` disponible globalement)
pipx install .

# Installation développeur (avec les tests)
pip install -e ".[dev]" --break-system-packages
```

**Dépendance externe requise pour les protocoles AD** (SMB/LDAP/WinRM/RDP/SSH) :
[NetExec](https://github.com/Pennyw0rth/NetExec), installable via `pipx install netexec`.
Le protocole `o365` n'en a pas besoin (appel HTTP direct).

## Gestion du mot de passe — sécurité

Ne jamais utiliser `--password` en clair si évitable : visible dans
l'historique shell et via `ps aux` pour tout utilisateur du système. Ordre de
priorité de résolution, du plus sûr au moins sûr :

1. `--password-file chemin.txt` (recommandé)
2. Variable d'environnement `SPRAYCTL_PASSWORD`
3. Prompt interactif masqué (si rien n'est fourni)
4. `--password` en clair (déconseillé — un avertissement s'affiche à l'écran)

Le mot de passe n'est **jamais** écrit dans les logs (ANSI ou JSON).

## Guide d'utilisation

### Étape 1 — Découvrir la vraie politique de lockout

**Cas normal : LDAP accessible (anonyme ou authentifié)**

```bash
sprayctl discover --dc-ip 10.10.10.10 --domain-dn "DC=corp,DC=local"
```

Lit `lockoutThreshold`, `lockoutDuration`, `lockOutObservationWindow` sur
l'objet domaine, et vérifie aussi les Fine-Grained Password Policies (PSO)
qui peuvent être plus restrictives sur certains groupes. Retourne la
politique la plus stricte trouvée.

Avec un compte authentifié (nécessaire pour lire les FGPP en général) :

```bash
sprayctl discover --dc-ip 10.10.10.10 --domain-dn "DC=corp,DC=local" \
    --username "CORP\\lowpriv" --password-file lowpriv_pw.txt
```

**Cas LDAP fermé (AD durci, bind anonyme désactivé)**

Utilise un compte de test **jetable** fourni explicitement par le client pour
mesurer le seuil réel par test contrôlé :

```bash
sprayctl discover-empirical --dc-ip 10.10.10.10 \
    --test-username test.spray@corp.local --password-file test_pw.txt \
    --use-ssl --max-attempts 10
```

⚠️ **Ce test verrouille délibérément le compte de test fourni** — c'est le
mécanisme de mesure, pas un bug. Une confirmation explicite est demandée
avant de lancer (sauf `--yes`). `max_attempts` est plafonné à 20 par sécurité,
non contournable. N'utiliser **jamais** cette commande sur un compte réel.

Ajouter `--measure-duration` pour aussi mesurer la durée réelle du
verrouillage (rallonge significativement le test — à réserver si le temps de
mission le permet).

### Étape 2 — Lancer la campagne en dry-run (par défaut)

```bash
sprayctl spray --service CORP-AD --protocol smb --target 10.10.10.10 \
    --domain CORP --users users.txt --password-file pw.txt \
    --threshold 5 --window-minutes 30
```

Sans `--execute`, **aucune tentative réelle n'est envoyée** — la sortie
simule ce qui serait fait (utilisateurs exclus car trop proches du seuil,
délais simulés). C'est le comportement par défaut, volontairement.

Protocoles supportés : `smb`, `ldap`, `winrm`, `rdp`, `ssh` (via NetExec) et
`o365` (via `--tenant` au lieu de `--target`/`--domain`).

### Étape 3 — Exécution réelle

```bash
sprayctl spray --service CORP-AD --protocol smb --target 10.10.10.10 \
    --domain CORP --users users.txt --password-file pw.txt \
    --threshold 5 --window-minutes 30 --execute
```

`--execute` déclenche une **confirmation explicite** (`y/N`) rappelant le
nombre de comptes ciblés et le seuil de sécurité calculé, sauf `--yes`. La
campagne s'arrête **automatiquement** dès qu'un verrouillage réel est
détecté dans la sortie de NetExec, sauf `--ignore-lockout` (à éviter).

Exemple O365 :

```bash
sprayctl spray --service O365-CORP --protocol o365 --tenant corp.onmicrosoft.com \
    --users users.txt --password-file pw.txt \
    --threshold 3 --window-minutes 60 --execute
```

Pour O365, un mot de passe valide mais bloqué par MFA (`AADSTS50076`) est
comptabilisé comme un **succès** dans les résultats — le password est
correct, c'est une information précieuse même sans accès complet.

### Étape 4 — Suivi en direct

```bash
sprayctl status --service CORP-AD --threshold 5 --window-minutes 30
```

Affiche un tableau coloré de l'état de chaque compte (nombre d'échecs dans
la fenêtre, seuil sûr, niveau de risque LOW/MEDIUM/HIGH). Repasser les mêmes
`--threshold`/`--window-minutes` que lors du `spray` initial pour un état
fiable — sinon un avertissement s'affiche.

### Traçabilité contractuelle (recommandé en mission)

Ajouter `--audit-log fichier.jsonl` à n'importe quelle sous-commande pour
consigner un log structuré, exploitable dans le rapport final :

```bash
sprayctl spray --service CORP-AD --protocol smb --target 10.10.10.10 \
    --domain CORP --users users.txt --password-file pw.txt \
    --threshold 5 --window-minutes 30 --execute \
    --audit-log mission_corp.jsonl --operator jdupont --mission-id MISSION-2026-042
```

Format JSON Lines (un événement par ligne) : horodatage précis de chaque
tentative, opérateur, référence de mission, résumé de campagne. **Le mot de
passe n'y est jamais écrit.** Le fichier reste exploitable même si la
campagne est interrompue brutalement (Ctrl+C, crash).

Pour en extraire un résumé a posteriori :

```bash
python3 -c "from sprayctl.audit_log import summarize; print(summarize('mission_corp.jsonl'))"
```

## Options de référence

| Option | Sous-commandes | Description |
|---|---|---|
| `--password-file` | toutes | Fichier contenant le mot de passe (recommandé) |
| `$SPRAYCTL_PASSWORD` | toutes | Variable d'environnement alternative |
| `--execute` | `spray` | Sans ce flag : dry-run uniquement |
| `--yes` | `spray`, `discover-empirical` | Saute la confirmation explicite |
| `--ignore-lockout` | `spray` | **Dangereux** : ignore le kill-switch sur lockout détecté |
| `--safety-margin` | `spray` | Fraction du seuil réel à ne jamais dépasser (défaut 0.8) |
| `--audit-log` | toutes | Fichier `.jsonl` de traçabilité contractuelle |
| `--use-ssl` | `discover-empirical` | LDAPS — fortement recommandé pour ce mode |
| `--max-attempts` | `discover-empirical` | Plafonné à 20, non contournable |

## Tests

```bash
pytest tests/ -v
```

68 tests couvrent en priorité la logique de seuil/fenêtre de l'orchestrateur
(le point le plus critique — une erreur ici peut verrouiller des comptes
clients réels en mission), la résolution sécurisée du mot de passe, le
parsing des codes d'erreur AD, et le nettoyage du fichier users (dédup,
commentaires, lignes vides).

## Sécurité — récapitulatif

- **Dry-run par défaut** partout ; `--execute` est obligatoire pour toute
  tentative réelle, avec confirmation explicite en plus.
- **Kill-switch automatique** : arrêt dès qu'un lockout est détecté dans la
  sortie du connecteur, indépendamment de la politique estimée en amont.
- **Mot de passe jamais loggé** en clair, ni dans les sorties terminal, ni
  dans l'audit log JSON.
- Toujours lancer `discover` (ou `discover-empirical` si LDAP est fermé)
  avant `spray`, pour un `--threshold` réel plutôt que deviné à la main.
- Le connecteur NetExec passe le mot de passe en argument de subprocess
  (limitation de l'interface CLI de netexec lui-même) — visible via `ps aux`
  pour les autres utilisateurs locaux du même système. Utiliser une VM
  d'attaque dédiée mono-utilisateur.
- La discovery LDAP authentifiée sans `--username`/`use_ssl=True` envoie les
  credentials en clair (LDAP simple bind, pas de STARTTLS). Réserver au lab
  ou activer LDAPS en conditions réelles.
- `discover-empirical` **verrouille délibérément** le compte de test fourni
  — utiliser exclusivement un compte jetable créé pour cet usage, jamais un
  compte réel.

## Limitations connues

- Le parsing de la sortie NetExec (`_parse_output` dans `connectors/netexec.py`)
  dépend du format d'affichage texte de l'outil — susceptible de nécessiter
  un ajustement si NetExec change son format de sortie.
- La mesure empirique de la fenêtre d'observation (`window_minutes`) via
  `--measure-duration` est une approximation conservative basée sur la durée
  de verrouillage mesurée, pas une lecture directe de `lockOutObservationWindow`.
- Smart Lockout côté O365 est plus complexe qu'un simple compteur (notion de
  "familiarité" IP/device) — la détection reste best-effort via les codes AADSTS.
