"""
Tests unitaires pour EmpiricalLockoutDiscovery.

Ce module fait des vrais binds LDAP réseau — on ne teste ici que la
logique pure et testable sans DC réel : parsing des codes d'erreur AD,
validation des paramètres, et garde-fous de sécurité (hard cap
max_attempts, refus d'un compte/mot de passe vide).
"""

import pytest

from sprayctl.empirical_discovery import (
    EmpiricalLockoutDiscovery,
    _extract_ad_data_code,
    AD_DATA_CODES,
    MAX_ATTEMPTS_HARD_CAP,
)


# ------------------------------------------------------------------ #
# _extract_ad_data_code — parsing des messages d'erreur LDAP/AD
# ------------------------------------------------------------------ #

class TestExtractAdDataCode:
    def test_extracts_locked_account_code(self):
        msg = ("80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, "
               "data 775, v4563")
        assert _extract_ad_data_code(msg) == "775"

    def test_extracts_invalid_credentials_code(self):
        msg = ("80090308: LdapErr: DSID-0C090442, comment: AcceptSecurityContext error, "
               "data 52e, v4563")
        assert _extract_ad_data_code(msg) == "52e"

    def test_returns_none_on_empty_message(self):
        assert _extract_ad_data_code("") is None
        assert _extract_ad_data_code(None) is None

    def test_returns_none_when_no_data_code_present(self):
        assert _extract_ad_data_code("some unrelated error message") is None

    def test_known_codes_mapping_contains_locked(self):
        assert AD_DATA_CODES["775"] == "account_locked"
        assert AD_DATA_CODES["533"] == "account_disabled"


# ------------------------------------------------------------------ #
# Validation des paramètres — garde-fous de sécurité
# ------------------------------------------------------------------ #

class TestEmpiricalDiscoveryValidation:
    def test_rejects_empty_dc_ip(self):
        with pytest.raises(ValueError):
            EmpiricalLockoutDiscovery(dc_ip="", test_username="t", correct_password="p")

    def test_rejects_empty_username(self):
        with pytest.raises(ValueError):
            EmpiricalLockoutDiscovery(dc_ip="10.0.0.1", test_username="", correct_password="p")

    def test_rejects_empty_password(self):
        with pytest.raises(ValueError):
            EmpiricalLockoutDiscovery(dc_ip="10.0.0.1", test_username="t", correct_password="")

    def test_rejects_max_attempts_above_hard_cap(self):
        with pytest.raises(ValueError):
            EmpiricalLockoutDiscovery(
                dc_ip="10.0.0.1", test_username="t", correct_password="p",
                max_attempts=MAX_ATTEMPTS_HARD_CAP + 1,
            )

    def test_accepts_max_attempts_at_hard_cap(self):
        # ne doit pas lever — exactement à la limite
        d = EmpiricalLockoutDiscovery(
            dc_ip="10.0.0.1", test_username="t", correct_password="p",
            max_attempts=MAX_ATTEMPTS_HARD_CAP,
        )
        assert d.max_attempts == MAX_ATTEMPTS_HARD_CAP

    def test_rejects_zero_or_negative_max_attempts(self):
        with pytest.raises(ValueError):
            EmpiricalLockoutDiscovery(dc_ip="10.0.0.1", test_username="t",
                                       correct_password="p", max_attempts=0)
        with pytest.raises(ValueError):
            EmpiricalLockoutDiscovery(dc_ip="10.0.0.1", test_username="t",
                                       correct_password="p", max_attempts=-1)

    def test_warns_without_ssl(self, capsys):
        EmpiricalLockoutDiscovery(dc_ip="10.0.0.1", test_username="t",
                                   correct_password="p", use_ssl=False)
        captured = capsys.readouterr()
        assert "EN CLAIR" in captured.out

    def test_no_warning_with_ssl(self, capsys):
        EmpiricalLockoutDiscovery(dc_ip="10.0.0.1", test_username="t",
                                   correct_password="p", use_ssl=True)
        captured = capsys.readouterr()
        assert "EN CLAIR" not in captured.out


# ------------------------------------------------------------------ #
# measure_threshold — logique de détection (avec _try_bind mocké)
# ------------------------------------------------------------------ #

class TestMeasureThresholdLogic:
    def test_detects_lockout_at_correct_attempt(self, monkeypatch):
        """Simule un verrouillage après exactement 3 échecs, sans réseau réel."""
        d = EmpiricalLockoutDiscovery(
            dc_ip="10.0.0.1", test_username="t", correct_password="p",
            max_attempts=10, delay_between_attempts=0,  # pas d'attente réelle en test
        )

        call_count = {"n": 0}

        def fake_try_bind(password):
            call_count["n"] += 1
            if call_count["n"] >= 3:
                return False, "775"  # verrouillé au 3e essai
            return False, "52e"  # invalid credentials avant ça

        monkeypatch.setattr(d, "_try_bind", fake_try_bind)
        threshold = d.measure_threshold()
        assert threshold == 3

    def test_returns_none_if_never_locked(self, monkeypatch):
        d = EmpiricalLockoutDiscovery(
            dc_ip="10.0.0.1", test_username="t", correct_password="p",
            max_attempts=5, delay_between_attempts=0,
        )
        monkeypatch.setattr(d, "_try_bind", lambda password: (False, "52e"))
        assert d.measure_threshold() is None

    def test_aborts_if_unexpectedly_succeeds(self, monkeypatch):
        """Si le bind avec le mauvais mot de passe réussit (anomalie), on
        n'invente pas un threshold — on retourne None plutôt qu'un résultat
        non fiable."""
        d = EmpiricalLockoutDiscovery(
            dc_ip="10.0.0.1", test_username="t", correct_password="p",
            max_attempts=5, delay_between_attempts=0,
        )
        monkeypatch.setattr(d, "_try_bind", lambda password: (True, None))
        assert d.measure_threshold() is None


# ------------------------------------------------------------------ #
# run_full_measurement — orchestration haut niveau
# ------------------------------------------------------------------ #

class TestRunFullMeasurement:
    def test_fallback_if_account_already_locked(self, monkeypatch):
        d = EmpiricalLockoutDiscovery(
            dc_ip="10.0.0.1", test_username="t", correct_password="p",
            delay_between_attempts=0,
        )
        monkeypatch.setattr(d, "verify_account_not_locked", lambda: False)
        result = d.run_full_measurement()
        assert result == {"threshold": 3, "window_minutes": 15.0}

    def test_uses_measured_threshold_when_available(self, monkeypatch):
        d = EmpiricalLockoutDiscovery(
            dc_ip="10.0.0.1", test_username="t", correct_password="p",
            delay_between_attempts=0,
        )
        monkeypatch.setattr(d, "verify_account_not_locked", lambda: True)
        monkeypatch.setattr(d, "measure_threshold", lambda: 4)
        result = d.run_full_measurement(measure_duration=False)
        assert result["threshold"] == 4
        assert result["window_minutes"] == 30.0  # défaut, non mesurée

    def test_fallback_if_no_lockout_detected(self, monkeypatch):
        d = EmpiricalLockoutDiscovery(
            dc_ip="10.0.0.1", test_username="t", correct_password="p",
            delay_between_attempts=0,
        )
        monkeypatch.setattr(d, "verify_account_not_locked", lambda: True)
        monkeypatch.setattr(d, "measure_threshold", lambda: None)
        result = d.run_full_measurement()
        assert result == {"threshold": 10, "window_minutes": 30.0}
