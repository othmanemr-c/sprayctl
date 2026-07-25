"""
Audit Log - Logging structuré JSON
=====================================

Objectif : produire un log exploitable pour la traçabilité contractuelle
d'une mission de pentest (obligatoire dans la plupart des méthodologies :
horodatage précis de chaque tentative, preuve du respect du scope/rythme,
justificatif en cas de question du client sur un incident).

Format : JSON Lines (.jsonl) — un événement JSON par ligne, append-only,
facilement parsable ligne par ligne même sur un fichier volumineux, et
directement important dans un tableur/SIEM sans framework supplémentaire.

Le mot de passe n'est JAMAIS écrit dans ce log, sous aucune forme.

Usage :
    logger = AuditLogger("mission_corp_2026.jsonl", operator="jdupont")
    logger.log_campaign_start(service="CORP-AD", protocol="smb", target="10.10.10.10", total_users=50)
    logger.log_attempt(service="CORP-AD", username="user1", success=False)
    logger.log_lockout_detected(service="CORP-AD", username="user1")
    logger.log_campaign_end(service="CORP-AD", attempted=12, successes=1)
"""

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = "1.0"


class AuditLogger:
    def __init__(self, path: str, operator: Optional[str] = None,
                 mission_id: Optional[str] = None):
        """
        path        : chemin du fichier .jsonl (créé/complété, jamais écrasé)
        operator    : identifiant du pentester (pour la traçabilité en équipe)
        mission_id  : référence de mission/contrat, si applicable
        """
        self.path = Path(path)
        self.operator = operator or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        self.mission_id = mission_id
        self.hostname = socket.gethostname()

        # crée le fichier et son dossier parent si besoin, sans écraser un log existant
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _write(self, event: dict):
        event["schema_version"] = SCHEMA_VERSION
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["operator"] = self.operator
        event["hostname"] = self.hostname
        if self.mission_id:
            event["mission_id"] = self.mission_id

        # append-only, une ligne JSON par événement — jamais de password ici
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    # ------------------------------------------------------------------ #
    # Événements de campagne
    # ------------------------------------------------------------------ #

    def log_campaign_start(self, service: str, protocol: str, total_users: int,
                            target: Optional[str] = None, tenant: Optional[str] = None,
                            threshold: Optional[int] = None, window_minutes: Optional[float] = None,
                            dry_run: bool = True):
        self._write({
            "event_type": "campaign_start",
            "service": service,
            "protocol": protocol,
            "target": target,
            "tenant": tenant,
            "total_users": total_users,
            "threshold": threshold,
            "window_minutes": window_minutes,
            "dry_run": dry_run,
        })

    def log_campaign_end(self, service: str, attempted: int, successes: int,
                          stopped_on_lockout: bool = False):
        self._write({
            "event_type": "campaign_end",
            "service": service,
            "attempted": attempted,
            "successes": successes,
            "stopped_on_lockout": stopped_on_lockout,
        })

    def log_attempt(self, service: str, username: str, success: bool,
                     admin: bool = False, mfa_required: bool = False):
        self._write({
            "event_type": "attempt",
            "service": service,
            "username": username,
            "success": success,
            "admin": admin,
            "mfa_required": mfa_required,
        })

    def log_skip(self, service: str, username: str, reason: str = "near_lockout_threshold"):
        self._write({
            "event_type": "skip",
            "service": service,
            "username": username,
            "reason": reason,
        })

    def log_lockout_detected(self, service: str, username: str):
        self._write({
            "event_type": "lockout_detected",
            "service": service,
            "username": username,
        })

    def log_discovery(self, method: str, service: str, threshold: int, window_minutes: float,
                       source: Optional[str] = None):
        """method : 'ldap' ou 'empirical'."""
        self._write({
            "event_type": "discovery",
            "method": method,
            "service": service,
            "threshold": threshold,
            "window_minutes": window_minutes,
            "source": source,
        })


# ---------------------------------------------------------------------- #
# Lecture / synthèse (utile pour générer un extrait pour le rapport final)
# ---------------------------------------------------------------------- #

def read_events(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    events = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # ligne corrompue — ignorée plutôt que de tout faire planter
    return events


def summarize(path: str) -> dict:
    """Petit résumé exploitable pour la section méthodologie d'un rapport."""
    events = read_events(path)
    attempts = [e for e in events if e.get("event_type") == "attempt"]
    campaigns = [e for e in events if e.get("event_type") == "campaign_start"]
    lockouts = [e for e in events if e.get("event_type") == "lockout_detected"]

    return {
        "total_campaigns": len(campaigns),
        "total_attempts": len(attempts),
        "total_successes": sum(1 for a in attempts if a.get("success")),
        "total_lockouts_detected": len(lockouts),
        "services": sorted(set(e.get("service") for e in events if e.get("service"))),
    }


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        log_path = f"{tmp}/demo.jsonl"
        logger = AuditLogger(log_path, operator="demo_pentester", mission_id="MISSION-2026-042")

        logger.log_discovery(method="ldap", service="CORP-AD", threshold=5, window_minutes=30, source="default")
        logger.log_campaign_start(service="CORP-AD", protocol="smb", target="10.10.10.10",
                                   total_users=3, threshold=5, window_minutes=30, dry_run=True)
        logger.log_attempt(service="CORP-AD", username="jdupont", success=False)
        logger.log_attempt(service="CORP-AD", username="amartin", success=True, admin=True)
        logger.log_skip(service="CORP-AD", username="svincent")
        logger.log_campaign_end(service="CORP-AD", attempted=2, successes=1)

        print(f"--- {log_path} ---")
        print(Path(log_path).read_text())
        print("--- summarize() ---")
        print(summarize(log_path))
