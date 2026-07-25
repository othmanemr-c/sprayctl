"""
Adaptive Password Spray Orchestrator - Module 2 & 3
=====================================================

Objectif : centraliser l'état de tentatives par (user, service) et ne jamais
dépasser un seuil de sécurité dérivé de la politique de lockout réelle,
avec jitter pour éviter les patterns détectables par un SOC.

Ce module NE contient PAS les connecteurs d'authentification (Module 4).
Il expose juste `should_attempt()` / `record_attempt()` que tes wrappers
CrackMapExec / o365spray / crowbar doivent appeler avant/après chaque essai.

Usage prévu :
    orch = SprayOrchestrator("campaign.db")
    orch.set_policy("CORP-AD", threshold=5, window_minutes=30, safety_margin=0.8)

    for user, password in await orch.next_batch("CORP-AD", users, dry_run=True):
        result = my_smb_connector(user, password)
        orch.record_attempt("CORP-AD", user, success=result.success)
"""

import asyncio
import random
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from .display import log_skip, log_dry_run

MAX_USERNAME_LEN = 256
MAX_SERVICE_LEN = 128


@dataclass
class LockoutPolicy:
    service: str
    threshold: int              # nb d'échecs avant lockout (observé/déclaré)
    window_minutes: float        # fenêtre d'observation (observationWindow AD)
    safety_margin: float = 0.8  # on ne consomme jamais plus de 80% du seuil
    min_delay_seconds: float = 3.0   # délai plancher entre 2 tentatives (même user)
    jitter_seconds: float = 5.0      # variation aléatoire ajoutée au délai

    def __post_init__(self):
        if self.threshold < 0:
            raise ValueError("threshold ne peut pas être négatif")
        if self.window_minutes <= 0:
            raise ValueError("window_minutes doit être strictement positif")
        if not 0 < self.safety_margin <= 1:
            raise ValueError("safety_margin doit être dans ]0, 1]")

    @property
    def safe_threshold(self) -> int:
        # jamais en dessous de 1 pour éviter une division par zéro / blocage total
        return max(1, int(self.threshold * self.safety_margin))


class SprayOrchestrator:
    def __init__(self, db_path: str = "spray_state.db"):
        self.db_path = db_path
        self._policies: dict[str, LockoutPolicy] = {}
        self._init_db()

    # ------------------------------------------------------------------ #
    # Setup
    # ------------------------------------------------------------------ #

    def _init_db(self):
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("""
                CREATE TABLE IF NOT EXISTS attempts (
                    service      TEXT NOT NULL,
                    username     TEXT NOT NULL,
                    attempted_at TEXT NOT NULL,
                    success      INTEGER NOT NULL DEFAULT 0
                )
            """)
            c.execute("""
                CREATE INDEX IF NOT EXISTS idx_service_user_time
                ON attempts(service, username, attempted_at)
            """)

    @contextmanager
    def _conn(self):
        """Connexion SQLite correctement fermée après usage.

        NOTE : `sqlite3.Connection` utilisée nue comme context manager ne
        FERME PAS la connexion (elle ne fait que commit/rollback) — c'était
        une fuite de handle dans la version précédente. Ce wrapper garantit
        une fermeture systématique, y compris en cas d'exception.
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def set_policy(self, service: str, threshold: int, window_minutes: float,
                    safety_margin: float = 0.8, min_delay_seconds: float = 3.0,
                    jitter_seconds: float = 5.0):
        """Enregistre la politique de lockout pour un service donné.

        threshold/window_minutes doivent venir de la Module 1 (discovery LDAP
        ou test contrôlé) — ne jamais deviner ces valeurs à l'aveugle.
        """
        self._policies[service] = LockoutPolicy(
            service=service,
            threshold=threshold,
            window_minutes=window_minutes,
            safety_margin=safety_margin,
            min_delay_seconds=min_delay_seconds,
            jitter_seconds=jitter_seconds,
        )

    def get_policy(self, service: str) -> Optional[LockoutPolicy]:
        """Accesseur public — utilisé notamment par l'audit log pour
        journaliser threshold/window sans dépendre d'un attribut privé."""
        return self._policies.get(service)

    # ------------------------------------------------------------------ #
    # Lecture d'état
    # ------------------------------------------------------------------ #

    def _fail_count_in_window(self, service: str, username: str, window_minutes: float) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
        with self._conn() as c:
            row = c.execute(
                """SELECT COUNT(*) as n FROM attempts
                   WHERE service = ? AND username = ? AND attempted_at >= ? AND success = 0""",
                (service, username, cutoff),
            ).fetchone()
            return row["n"]

    def should_attempt(self, service: str, username: str) -> bool:
        """Retourne False si on approche trop près du seuil de lockout."""
        policy = self._policies.get(service)
        if not policy:
            raise ValueError(f"Aucune politique définie pour '{service}'. Appelle set_policy() d'abord.")

        fails = self._fail_count_in_window(service, username, policy.window_minutes)
        return fails < policy.safe_threshold

    def record_attempt(self, service: str, username: str, success: bool):
        if len(username) > MAX_USERNAME_LEN or len(service) > MAX_SERVICE_LEN:
            raise ValueError("username/service dépasse la longueur maximale autorisée")
        if not username.strip() or not service.strip():
            raise ValueError("username/service ne peut pas être vide")

        with self._conn() as c:
            c.execute(
                "INSERT INTO attempts (service, username, attempted_at, success) VALUES (?, ?, ?, ?)",
                (service, username, datetime.now(timezone.utc).isoformat(), int(success)),
            )

    def status_report(self, service: str) -> list[dict]:
        """Snapshot pour le dashboard (Module 5)."""
        policy = self._policies.get(service)
        if not policy:
            return []
        with self._conn() as c:
            usernames = [r["username"] for r in c.execute(
                "SELECT DISTINCT username FROM attempts WHERE service = ?", (service,)
            )]
        report = []
        for u in usernames:
            fails = self._fail_count_in_window(service, u, policy.window_minutes)
            report.append({
                "username": u,
                "fails_in_window": fails,
                "safe_threshold": policy.safe_threshold,
                "risk": "HIGH" if fails >= policy.safe_threshold - 1 else
                        ("MEDIUM" if fails >= policy.safe_threshold // 2 else "LOW"),
            })
        return report

    # ------------------------------------------------------------------ #
    # Orchestration
    # ------------------------------------------------------------------ #

    async def next_batch(self, service: str, usernames: Iterable[str],
                          dry_run: bool = True):
        """Générateur async qui yield les users éligibles un par un,
        en respectant délai + jitter, en excluant ceux proches du lockout.

        dry_run=True : ne fait qu'afficher/logger ce qui SERAIT tenté,
        sans jamais réellement appeler un connecteur. À garder True
        jusqu'à validation explicite de la marge de sécurité.
        """
        policy = self._policies.get(service)
        if not policy:
            raise ValueError(f"Aucune politique définie pour '{service}'.")

        for username in usernames:
            if not self.should_attempt(service, username):
                log_skip(username, service)
                continue

            delay = policy.min_delay_seconds + random.uniform(0, policy.jitter_seconds)

            if dry_run:
                log_dry_run(username, service, delay)
            else:
                await asyncio.sleep(delay)

            yield username, delay


# ---------------------------------------------------------------------- #
# Exemple d'utilisation (à remplacer par un vrai connecteur en Module 4)
# ---------------------------------------------------------------------- #

async def demo():
    orch = SprayOrchestrator("demo_campaign.db")

    # Ces valeurs doivent venir de la discovery réelle (LDAP pwdPolicy), pas d'une supposition
    orch.set_policy("CORP-AD", threshold=5, window_minutes=30, safety_margin=0.8)

    users = [f"user{i}" for i in range(1, 6)]
    password = "Summer2026!"  # exemple

    async for username, delay in orch.next_batch("CORP-AD", users, dry_run=True):
        # Ici, en conditions réelles :
        # result = await cme_connector.try_login(username, password)
        # orch.record_attempt("CORP-AD", username, success=result.success)
        orch.record_attempt("CORP-AD", username, success=False)  # simulate un échec

    from .display import print_status_table
    print("\n--- Status report ---")
    print_status_table(orch.status_report("CORP-AD"))


if __name__ == "__main__":
    asyncio.run(demo())
