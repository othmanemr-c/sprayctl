"""
Colored Terminal Output - Module 5 (version légère)
======================================================

Remplace le dashboard TUI par de simples codes ANSI directement dans les
prints existants. Zéro dépendance, marche partout, suffisant pour suivre
une campagne en temps réel dans un terminal pendant une mission.

Usage : importer les fonctions et les utiliser à la place de print() nu
dans spray_orchestrator.py et netexec_connector.py.
"""

import sys


class C:
    """Codes couleur ANSI. RESET impératif après chaque usage."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"

    BG_RED = "\033[41m"


def _supports_color() -> bool:
    # désactive proprement si sortie redirigée vers un fichier/pipe
    return sys.stdout.isatty()


_COLOR = _supports_color()


def _c(text: str, color: str) -> str:
    if not _COLOR:
        return text
    return f"{color}{text}{C.RESET}"


# ---------------------------------------------------------------------- #
# Fonctions prêtes à l'emploi, à substituer aux print() existants
# ---------------------------------------------------------------------- #

def log_skip(username: str, service: str):
    print(_c(f"[SKIP]", C.GRAY) + f" {username}@{service} proche du seuil de lockout — exclu")


def log_dry_run(username: str, service: str, delay: float):
    print(_c(f"[DRY-RUN]", C.CYAN) + f" {username}@{service} — attente simulée {delay:.1f}s")


def log_success(username: str, admin: bool = False):
    tag = _c("[SUCCESS]", C.BOLD + C.GREEN)
    extra = _c(" ADMIN", C.BOLD + C.MAGENTA) if admin else ""
    print(f"{tag} {username}{extra}")


def log_fail(username: str):
    print(_c("[fail]", C.GRAY) + f" {username}")


def log_locked(username: str):
    print(_c("[LOCKED]", C.BOLD + C.RED) + f" {username} — verrouillage détecté")


def log_lockout_stop(username: str):
    print()
    print(_c(f"  /!\\ LOCKOUT DÉTECTÉ SUR {username} — CAMPAGNE ARRÊTÉE  ", C.BG_RED + C.BOLD))
    print(_c("Vérifie la politique réelle avant de reprendre.", C.YELLOW))
    print()


def log_policy_loaded(source: str, threshold: int, window: float):
    print(_c("[+]", C.GREEN) + f" Politique chargée : source={source} "
          + _c(f"threshold={threshold}", C.YELLOW) + f" window={window:.1f}min")


def log_fallback_policy():
    print(_c("[!]", C.YELLOW) + " Discovery impossible — fallback prudent appliqué "
          + _c("(threshold=3, window=15min)", C.DIM))


def print_status_table(report: list[dict]):
    """Affiche le status_report() de l'orchestrateur en tableau coloré."""
    if not report:
        print(_c("Aucune donnée pour ce service.", C.GRAY))
        return

    risk_colors = {"LOW": C.GREEN, "MEDIUM": C.YELLOW, "HIGH": C.RED}

    header = f"{'USER':<20} {'FAILS':>6} {'SEUIL':>6} {'RISQUE':>8}"
    print(_c(header, C.BOLD))
    print(_c("-" * len(header), C.GRAY))

    for entry in report:
        risk = entry["risk"]
        color = risk_colors.get(risk, C.RESET)
        line = f"{entry['username']:<20} {entry['fails_in_window']:>6} " \
               f"{entry['safe_threshold']:>6} {risk:>8}"
        print(_c(line, color))


# ---------------------------------------------------------------------- #
# Démo autonome
# ---------------------------------------------------------------------- #

if __name__ == "__main__":
    log_policy_loaded("default", threshold=5, window=30.0)
    log_dry_run("jdupont", "CORP-AD", 4.7)
    log_success("amartin", admin=True)
    log_fail("svincent")
    log_locked("bdurand")
    log_lockout_stop("bdurand")
    log_skip("cleroy", "CORP-AD")

    print()
    print_status_table([
        {"username": "jdupont", "fails_in_window": 1, "safe_threshold": 4, "risk": "LOW"},
        {"username": "amartin", "fails_in_window": 3, "safe_threshold": 4, "risk": "MEDIUM"},
        {"username": "bdurand", "fails_in_window": 4, "safe_threshold": 4, "risk": "HIGH"},
    ])
