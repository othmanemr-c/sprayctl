"""
Tests unitaires pour SprayOrchestrator.

C'est le cœur du projet : should_attempt() est ce qui empêche un lockout
réel en mission. Ces tests couvrent en priorité les cas limites (seuil
exact, marge de sécurité, fenêtre temporelle) car une erreur ici a un
impact direct sur un client en conditions réelles.

Lancer : pytest tests/ -v
"""

import asyncio
import time

import pytest

from sprayctl.orchestrator import SprayOrchestrator, LockoutPolicy


@pytest.fixture
def orch(tmp_path):
    db_path = tmp_path / "test_campaign.db"
    return SprayOrchestrator(str(db_path))


# ------------------------------------------------------------------ #
# LockoutPolicy — validation et calcul du seuil sûr
# ------------------------------------------------------------------ #

class TestLockoutPolicy:
    def test_safe_threshold_applies_margin(self):
        policy = LockoutPolicy(service="X", threshold=5, window_minutes=30, safety_margin=0.8)
        assert policy.safe_threshold == 4  # int(5 * 0.8) = 4

    def test_safe_threshold_never_below_one(self):
        # threshold=1 avec marge 0.8 -> int(0.8) = 0, doit être clampé à 1
        policy = LockoutPolicy(service="X", threshold=1, window_minutes=30, safety_margin=0.8)
        assert policy.safe_threshold == 1

    def test_safe_threshold_zero_threshold(self):
        # threshold=0 signifie généralement "lockout désactivé" côté AD ;
        # l'orchestrateur reste tout de même prudent et impose 1 comme plancher
        policy = LockoutPolicy(service="X", threshold=0, window_minutes=30, safety_margin=0.8)
        assert policy.safe_threshold == 1

    def test_rejects_negative_threshold(self):
        with pytest.raises(ValueError):
            LockoutPolicy(service="X", threshold=-1, window_minutes=30)

    def test_rejects_zero_or_negative_window(self):
        with pytest.raises(ValueError):
            LockoutPolicy(service="X", threshold=5, window_minutes=0)
        with pytest.raises(ValueError):
            LockoutPolicy(service="X", threshold=5, window_minutes=-10)

    def test_rejects_invalid_safety_margin(self):
        with pytest.raises(ValueError):
            LockoutPolicy(service="X", threshold=5, window_minutes=30, safety_margin=0)
        with pytest.raises(ValueError):
            LockoutPolicy(service="X", threshold=5, window_minutes=30, safety_margin=1.5)


# ------------------------------------------------------------------ #
# should_attempt / record_attempt — le garde-fou principal
# ------------------------------------------------------------------ #

class TestShouldAttempt:
    def test_raises_if_no_policy_set(self, orch):
        with pytest.raises(ValueError):
            orch.should_attempt("UNKNOWN-SERVICE", "jdupont")

    def test_allows_first_attempt(self, orch):
        orch.set_policy("SVC", threshold=5, window_minutes=30, safety_margin=0.8)
        assert orch.should_attempt("SVC", "jdupont") is True

    def test_blocks_at_safe_threshold(self, orch):
        # threshold=5, margin=0.8 -> safe_threshold=4
        orch.set_policy("SVC", threshold=5, window_minutes=30, safety_margin=0.8)
        for _ in range(4):
            orch.record_attempt("SVC", "jdupont", success=False)
        # 4 échecs déjà enregistrés == safe_threshold -> doit bloquer le 5e
        assert orch.should_attempt("SVC", "jdupont") is False

    def test_allows_just_below_safe_threshold(self, orch):
        orch.set_policy("SVC", threshold=5, window_minutes=30, safety_margin=0.8)
        for _ in range(3):
            orch.record_attempt("SVC", "jdupont", success=False)
        # 3 échecs < safe_threshold(4) -> encore autorisé
        assert orch.should_attempt("SVC", "jdupont") is True

    def test_successes_do_not_count_toward_lockout(self, orch):
        orch.set_policy("SVC", threshold=5, window_minutes=30, safety_margin=0.8)
        for _ in range(10):
            orch.record_attempt("SVC", "jdupont", success=True)
        # uniquement les échecs comptent dans _fail_count_in_window
        assert orch.should_attempt("SVC", "jdupont") is True

    def test_users_are_isolated_from_each_other(self, orch):
        orch.set_policy("SVC", threshold=5, window_minutes=30, safety_margin=0.8)
        for _ in range(4):
            orch.record_attempt("SVC", "jdupont", success=False)
        # jdupont est bloqué, mais amartin n'a pas d'historique -> toujours autorisé
        assert orch.should_attempt("SVC", "jdupont") is False
        assert orch.should_attempt("SVC", "amartin") is True

    def test_services_are_isolated_from_each_other(self, orch):
        orch.set_policy("AD", threshold=5, window_minutes=30, safety_margin=0.8)
        orch.set_policy("O365", threshold=3, window_minutes=60, safety_margin=0.8)
        for _ in range(4):
            orch.record_attempt("AD", "jdupont", success=False)
        # même username mais service différent -> pas d'impact croisé
        assert orch.should_attempt("O365", "jdupont") is True

    def test_old_failures_outside_window_do_not_count(self, orch):
        import sqlite3
        from datetime import datetime, timedelta, timezone

        orch.set_policy("SVC", threshold=5, window_minutes=30, safety_margin=0.8)

        # insère manuellement un échec avec un timestamp vieux de 2h
        # (en dehors de la fenêtre de 30 minutes)
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with sqlite3.connect(orch.db_path) as c:
            c.execute(
                "INSERT INTO attempts (service, username, attempted_at, success) VALUES (?, ?, ?, ?)",
                ("SVC", "jdupont", old_ts, 0),
            )

        # 1 seul échec, mais hors fenêtre -> ne doit pas compter
        assert orch.should_attempt("SVC", "jdupont") is True


# ------------------------------------------------------------------ #
# record_attempt — validation d'entrée
# ------------------------------------------------------------------ #

class TestRecordAttemptValidation:
    def test_rejects_empty_username(self, orch):
        with pytest.raises(ValueError):
            orch.record_attempt("SVC", "", success=False)

    def test_rejects_empty_service(self, orch):
        with pytest.raises(ValueError):
            orch.record_attempt("", "jdupont", success=False)

    def test_rejects_oversized_username(self, orch):
        with pytest.raises(ValueError):
            orch.record_attempt("SVC", "a" * 500, success=False)


# ------------------------------------------------------------------ #
# status_report
# ------------------------------------------------------------------ #

class TestStatusReport:
    def test_empty_if_no_policy(self, orch):
        assert orch.status_report("UNKNOWN") == []

    def test_risk_levels(self, orch):
        orch.set_policy("SVC", threshold=10, window_minutes=30, safety_margin=0.8)
        # safe_threshold = 8

        orch.record_attempt("SVC", "low_user", success=False)          # 1 fail -> LOW
        for _ in range(4):
            orch.record_attempt("SVC", "medium_user", success=False)   # 4 fails -> MEDIUM
        for _ in range(7):
            orch.record_attempt("SVC", "high_user", success=False)     # 7 fails -> HIGH

        report = {r["username"]: r["risk"] for r in orch.status_report("SVC")}
        assert report["low_user"] == "LOW"
        assert report["medium_user"] == "MEDIUM"
        assert report["high_user"] == "HIGH"


# ------------------------------------------------------------------ #
# next_batch — orchestration async
# ------------------------------------------------------------------ #

class TestNextBatch:
    def test_dry_run_does_not_sleep(self, orch):
        orch.set_policy("SVC", threshold=5, window_minutes=30, safety_margin=0.8,
                         min_delay_seconds=100, jitter_seconds=0)  # délai énorme si non dry-run

        async def run():
            start = time.monotonic()
            results = []
            async for username, delay in orch.next_batch("SVC", ["u1", "u2"], dry_run=True):
                results.append(username)
            elapsed = time.monotonic() - start
            return results, elapsed

        results, elapsed = asyncio.run(run())
        assert results == ["u1", "u2"]
        assert elapsed < 1.0  # aucun sleep réel en dry-run

    def test_skips_users_near_threshold(self, orch):
        orch.set_policy("SVC", threshold=5, window_minutes=30, safety_margin=0.8,
                         min_delay_seconds=0, jitter_seconds=0)
        for _ in range(4):
            orch.record_attempt("SVC", "blocked_user", success=False)

        async def run():
            results = []
            async for username, delay in orch.next_batch(
                "SVC", ["blocked_user", "ok_user"], dry_run=True
            ):
                results.append(username)
            return results

        results = asyncio.run(run())
        assert "blocked_user" not in results
        assert "ok_user" in results

    def test_raises_without_policy(self, orch):
        async def run():
            async for _ in orch.next_batch("NO-POLICY", ["u1"]):
                pass

        with pytest.raises(ValueError):
            asyncio.run(run())


# ------------------------------------------------------------------ #
# Connexions SQLite — pas de fuite de handle
# ------------------------------------------------------------------ #

class TestConnectionHandling:
    def test_no_connection_leak_on_error(self, orch, tmp_path):
        """Vérifie que même en cas d'exception, la connexion est fermée
        (régression sur le bug initial : sqlite3.Connection en context
        manager nu ne fermait pas la connexion).
        """
        orch.set_policy("SVC", threshold=5, window_minutes=30)

        # provoque une erreur (username trop long) et vérifie qu'aucune
        # connexion ne reste ouverte en verrouillant le fichier ensuite
        with pytest.raises(ValueError):
            orch.record_attempt("SVC", "a" * 500, success=False)

        # si la connexion précédente avait fuité, celle-ci pourrait bloquer
        # sur un verrou WAL — on vérifie juste que ça ne lève rien d'inattendu
        orch.record_attempt("SVC", "jdupont", success=False)
        assert orch.should_attempt("SVC", "jdupont") is True
