"""
sprayctl - CLI unifié
=======================

Point d'entrée unique qui câble ensemble discovery, orchestrateur et
connecteurs. Aucune nouvelle logique métier ici — uniquement de
l'assemblage et de la gestion d'arguments.

Sous-commandes :
    sprayctl discover   -> lit la politique de lockout AD via LDAP
    sprayctl spray      -> lance une campagne (smb/ldap/winrm/o365...)
    sprayctl status      -> affiche le status_report() d'un service
"""

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

from .discovery import build_orchestrator_policy_from_ad
from .empirical_discovery import EmpiricalLockoutDiscovery, MAX_ATTEMPTS_HARD_CAP
from .orchestrator import SprayOrchestrator
from .audit_log import AuditLogger
from .display import print_status_table
from .connectors.netexec import NetExecConnector, run_campaign
from .connectors.o365 import O365Connector, O365ConnectorAdapter

MAX_USERS_FILE_LINES = 50_000
ENV_PASSWORD_VAR = "SPRAYCTL_PASSWORD"


def _read_users(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        print(f"[!] Fichier introuvable : {path}", file=sys.stderr)
        sys.exit(1)

    lines = p.read_text(errors="replace").splitlines()
    if len(lines) > MAX_USERS_FILE_LINES:
        print(f"[!] Fichier users trop volumineux (>{MAX_USERS_FILE_LINES} lignes) — "
              "probable erreur de fichier, arrêt par sécurité", file=sys.stderr)
        sys.exit(1)

    # dédup en préservant l'ordre, on ignore lignes vides et commentaires (#...)
    seen = set()
    users = []
    for line in lines:
        u = line.strip()
        if not u or u.startswith("#") or u in seen:
            continue
        seen.add(u)
        users.append(u)

    if not users:
        print(f"[!] Aucun username valide trouvé dans {path}", file=sys.stderr)
        sys.exit(1)

    return users


def _resolve_password(args) -> str:
    """Ordre de priorité, du plus sûr au moins sûr :
    1. --password-file (contenu lu depuis un fichier, jamais dans argv/historique)
    2. variable d'environnement SPRAYCTL_PASSWORD (pas dans argv, mais visible
       dans /proc/<pid>/environ pour le même utilisateur — mieux que argv qui
       est visible par TOUT utilisateur via `ps aux`)
    3. prompt interactif masqué (getpass) — le plus sûr en usage manuel
    4. --password en clair sur la ligne de commande — déconseillé, conservé
       uniquement pour compatibilité scripts CI/CD isolés
    """
    if getattr(args, "password_file", None):
        pw_path = Path(args.password_file)
        if not pw_path.exists():
            print(f"[!] --password-file introuvable : {args.password_file}", file=sys.stderr)
            sys.exit(1)
        return pw_path.read_text().strip()

    if os.environ.get(ENV_PASSWORD_VAR):
        return os.environ[ENV_PASSWORD_VAR]

    if getattr(args, "password", None):
        print("[!] ATTENTION : --password en clair est visible dans l'historique shell "
              "et via `ps aux` pour tout utilisateur du système. "
              f"Préfère --password-file ou la variable d'environnement {ENV_PASSWORD_VAR}.",
              file=sys.stderr)
        return args.password

    return getpass.getpass("Mot de passe : ")


# ------------------------------------------------------------------ #
# Sous-commande : discover
# ------------------------------------------------------------------ #

def cmd_discover(args):
    password = _resolve_password(args) if args.username else None
    kwargs = build_orchestrator_policy_from_ad(
        dc_ip=args.dc_ip,
        domain_dn=args.domain_dn,
        username=args.username,
        password=password,
    )

    if args.audit_log:
        AuditLogger(args.audit_log, operator=args.operator, mission_id=args.mission_id).log_discovery(
            method="ldap", service=args.domain_dn,
            threshold=kwargs["threshold"], window_minutes=kwargs["window_minutes"],
        )

    print(f"\nÀ utiliser dans 'sprayctl spray' :")
    print(f"  --threshold {kwargs['threshold']} --window-minutes {kwargs['window_minutes']:.1f}")


# ------------------------------------------------------------------ #
# Sous-commande : discover-empirical
# ------------------------------------------------------------------ #

def cmd_discover_empirical(args):
    print("!! Ce test VERROUILLE délibérément le compte de test fourni. "
          "Utilise UNIQUEMENT un compte jetable, jamais un compte réel. !!")
    if not args.yes:
        confirm = input(f"Confirmer le test sur '{args.test_username}' ? [y/N] ").strip().lower()
        if confirm != "y":
            print("Annulé.")
            sys.exit(0)

    correct_password = _resolve_password(args)

    try:
        discovery = EmpiricalLockoutDiscovery(
            dc_ip=args.dc_ip,
            test_username=args.test_username,
            correct_password=correct_password,
            use_ssl=args.use_ssl,
            max_attempts=args.max_attempts,
            delay_between_attempts=args.delay,
        )
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    kwargs = discovery.run_full_measurement(measure_duration=args.measure_duration)

    if args.audit_log:
        AuditLogger(args.audit_log, operator=args.operator, mission_id=args.mission_id).log_discovery(
            method="empirical", service=args.test_username,
            threshold=kwargs["threshold"], window_minutes=kwargs["window_minutes"],
        )

    print(f"\nÀ utiliser dans 'sprayctl spray' :")
    print(f"  --threshold {kwargs['threshold']} --window-minutes {kwargs['window_minutes']:.1f}")


# ------------------------------------------------------------------ #
# Sous-commande : spray
# ------------------------------------------------------------------ #

def cmd_spray(args):
    password = _resolve_password(args)

    orch = SprayOrchestrator(args.db)
    orch.set_policy(
        args.service,
        threshold=args.threshold,
        window_minutes=args.window_minutes,
        safety_margin=args.safety_margin,
    )

    users = _read_users(args.users)

    if args.protocol == "o365":
        if not args.tenant:
            print("[!] --tenant est requis pour le protocole o365", file=sys.stderr)
            sys.exit(1)
        connector = O365ConnectorAdapter(O365Connector(tenant=args.tenant))
    else:
        if not args.target:
            print("[!] --target est requis pour ce protocole", file=sys.stderr)
            sys.exit(1)
        try:
            connector = NetExecConnector(
                target=args.target,
                protocol=args.protocol,
                domain=args.domain,
            )
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)

    if args.execute and not args.yes:
        print(f"\nCampagne RÉELLE sur {len(users)} compte(s), service={args.service}, "
              f"protocole={args.protocol}, seuil sûr={int(args.threshold * args.safety_margin)}.")
        confirm = input("Confirmer le lancement réel ? [y/N] ").strip().lower()
        if confirm != "y":
            print("Annulé.")
            sys.exit(0)

    audit_log = None
    if args.audit_log:
        audit_log = AuditLogger(args.audit_log, operator=args.operator, mission_id=args.mission_id)

    asyncio.run(run_campaign(
        orch, connector, args.service, users, password,
        dry_run=not args.execute,
        stop_on_lockout_detected=not args.ignore_lockout,
        audit_log=audit_log,
        target=args.target,
        tenant=args.tenant,
    ))

    if not args.execute:
        print("\n[i] Mode dry-run (par défaut). Relance avec --execute pour un spray réel.")


# ------------------------------------------------------------------ #
# Sous-commande : status
# ------------------------------------------------------------------ #

def cmd_status(args):
    orch = SprayOrchestrator(args.db)
    if args.threshold is None or args.window_minutes is None:
        print("[!] --threshold/--window-minutes non fournis — affichage avec des valeurs "
              "par défaut (5/30min) qui peuvent ne pas refléter la vraie politique. "
              "Repasse les mêmes valeurs que lors du 'sprayctl spray' initial pour un état fiable.",
              file=sys.stderr)
    orch.set_policy(args.service, threshold=args.threshold or 5,
                     window_minutes=args.window_minutes or 30)
    print_status_table(orch.status_report(args.service))


# ------------------------------------------------------------------ #
# Parser principal
# ------------------------------------------------------------------ #

def _add_audit_args(parser: argparse.ArgumentParser):
    parser.add_argument("--audit-log", default=None,
                         help="Fichier .jsonl pour la traçabilité contractuelle de mission")
    parser.add_argument("--operator", default=None,
                         help="Identifiant du pentester (défaut : $USER)")
    parser.add_argument("--mission-id", default=None, help="Référence de mission/contrat")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sprayctl",
        description="Orchestrateur de password spray lockout-aware pour pentest interne/externe.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- discover ---
    p_disc = sub.add_parser("discover", help="Lit la politique de lockout AD via LDAP")
    p_disc.add_argument("--dc-ip", required=True, help="IP/hostname du Domain Controller")
    p_disc.add_argument("--domain-dn", required=True, help='Ex: "DC=corp,DC=local"')
    p_disc.add_argument("--username", default=None, help="Optionnel, sinon bind anonyme")
    p_disc.add_argument("--password", default=None,
                         help="Déconseillé (visible en clair) — préférer --password-file ou $SPRAYCTL_PASSWORD")
    p_disc.add_argument("--password-file", default=None, help="Fichier contenant le mot de passe")
    _add_audit_args(p_disc)
    p_disc.set_defaults(func=cmd_discover)

    # --- discover-empirical ---
    p_emp = sub.add_parser("discover-empirical",
                            help="Mesure le seuil de lockout par test contrôlé (LDAP fermé)")
    p_emp.add_argument("--dc-ip", required=True, help="IP/hostname du Domain Controller")
    p_emp.add_argument("--test-username", required=True,
                        help="Compte de test JETABLE — jamais un compte réel")
    p_emp.add_argument("--password", default=None,
                        help="Mot de passe CORRECT du compte de test (déconseillé en clair)")
    p_emp.add_argument("--password-file", default=None)
    p_emp.add_argument("--use-ssl", action="store_true", help="LDAPS — fortement recommandé")
    p_emp.add_argument("--max-attempts", type=int, default=10,
                        help=f"Plafond d'essais, max {MAX_ATTEMPTS_HARD_CAP}")
    p_emp.add_argument("--delay", type=float, default=2.0,
                        help="Délai en secondes entre chaque essai")
    p_emp.add_argument("--measure-duration", action="store_true",
                        help="Mesure aussi la durée réelle du verrouillage (rallonge le test)")
    p_emp.add_argument("--yes", action="store_true",
                        help="Ne pas demander de confirmation avant de verrouiller le compte de test")
    _add_audit_args(p_emp)
    p_emp.set_defaults(func=cmd_discover_empirical)

    # --- spray ---
    p_spray = sub.add_parser("spray", help="Lance une campagne de spray")
    p_spray.add_argument("--service", required=True, help='Identifiant libre, ex: "CORP-AD"')
    p_spray.add_argument("--protocol", required=True,
                          choices=["smb", "ldap", "winrm", "rdp", "ssh", "o365"])
    p_spray.add_argument("--target", help="IP/hostname cible (requis sauf pour o365)")
    p_spray.add_argument("--tenant", help="Tenant O365, ex: corp.onmicrosoft.com")
    p_spray.add_argument("--domain", help="Domaine NetBIOS/AD (pour smb/ldap/winrm)")
    p_spray.add_argument("--users", required=True, help="Fichier avec un username par ligne")
    p_spray.add_argument("--password", default=None,
                          help="Déconseillé (visible en clair) — préférer --password-file ou $SPRAYCTL_PASSWORD")
    p_spray.add_argument("--password-file", default=None, help="Fichier contenant le mot de passe")
    p_spray.add_argument("--threshold", type=int, required=True,
                          help="Seuil de lockout (voir 'sprayctl discover')")
    p_spray.add_argument("--window-minutes", type=float, required=True)
    p_spray.add_argument("--safety-margin", type=float, default=0.8)
    p_spray.add_argument("--db", default="campaign.db")
    p_spray.add_argument("--execute", action="store_true",
                          help="Sans ce flag : dry-run uniquement, aucune tentative réelle")
    p_spray.add_argument("--yes", action="store_true",
                          help="Ne pas demander de confirmation avant un --execute réel")
    p_spray.add_argument("--ignore-lockout", action="store_true",
                          help="DANGEREUX : ne pas arrêter la campagne si un lockout est détecté")
    _add_audit_args(p_spray)
    p_spray.set_defaults(func=cmd_spray)

    # --- status ---
    p_status = sub.add_parser("status", help="Affiche l'état d'une campagne en cours")
    p_status.add_argument("--service", required=True)
    p_status.add_argument("--db", default="campaign.db")
    p_status.add_argument("--threshold", type=int, default=None)
    p_status.add_argument("--window-minutes", type=float, default=None)
    p_status.set_defaults(func=cmd_status)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.", file=sys.stderr)
        sys.exit(130)
    except ValueError as e:
        print(f"[!] Erreur de configuration : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
