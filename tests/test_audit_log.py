"""
Tests unitaires pour AuditLogger.

Vérifie surtout deux choses critiques : le format JSONL est bien formé et
parsable, et le mot de passe n'apparaît JAMAIS dans le log, quelles que
soient les valeurs passées.
"""

import json

import pytest

from sprayctl.audit_log import AuditLogger, read_events, summarize


@pytest.fixture
def log_path(tmp_path):
    return str(tmp_path / "audit.jsonl")


class TestAuditLoggerBasics:
    def test_creates_file_if_missing(self, log_path):
        AuditLogger(log_path)
        import os
        assert os.path.exists(log_path)

    def test_does_not_overwrite_existing_log(self, log_path):
        logger1 = AuditLogger(log_path, operator="jdupont")
        logger1.log_attempt("SVC", "user1", success=False)

        logger2 = AuditLogger(log_path, operator="amartin")
        logger2.log_attempt("SVC", "user2", success=False)

        events = read_events(log_path)
        assert len(events) == 2  # les deux logs s'accumulent, rien n'est écrasé

    def test_each_line_is_valid_json(self, log_path):
        logger = AuditLogger(log_path)
        logger.log_attempt("SVC", "user1", success=True, admin=True)
        logger.log_skip("SVC", "user2")

        with open(log_path) as f:
            lines = [l for l in f.readlines() if l.strip()]

        assert len(lines) == 2
        for line in lines:
            json.loads(line)  # doit parser sans exception

    def test_events_include_operator_and_hostname(self, log_path):
        logger = AuditLogger(log_path, operator="jdupont", mission_id="M-042")
        logger.log_attempt("SVC", "user1", success=False)

        events = read_events(log_path)
        assert events[0]["operator"] == "jdupont"
        assert events[0]["mission_id"] == "M-042"
        assert "hostname" in events[0]
        assert "timestamp" in events[0]


class TestNoPasswordLeakage:
    """Le test le plus important du module : peu importe la méthode
    appelée, aucun mot de passe ne doit jamais apparaître dans le log."""

    def test_no_password_field_in_any_event_type(self, log_path):
        logger = AuditLogger(log_path, operator="jdupont")

        logger.log_campaign_start(service="SVC", protocol="smb", total_users=3,
                                   target="10.0.0.1", threshold=5, window_minutes=30)
        logger.log_attempt(service="SVC", username="user1", success=True)
        logger.log_skip(service="SVC", username="user2")
        logger.log_lockout_detected(service="SVC", username="user3")
        logger.log_discovery(method="ldap", service="SVC", threshold=5, window_minutes=30)
        logger.log_campaign_end(service="SVC", attempted=3, successes=1)

        raw_content = open(log_path).read()
        assert "password" not in raw_content.lower()

    def test_username_containing_word_password_is_not_a_false_positive(self, log_path):
        # cas limite : un username qui contiendrait le mot "password" ne
        # doit pas planter le test — on vérifie juste qu'aucun champ dédié
        # "password"/"pwd" n'existe dans le schéma
        logger = AuditLogger(log_path)
        logger.log_attempt(service="SVC", username="password_reset_svc", success=False)

        events = read_events(log_path)
        assert "password" not in events[0]
        assert "pwd" not in events[0]


class TestReadEvents:
    def test_returns_empty_list_for_missing_file(self, tmp_path):
        assert read_events(str(tmp_path / "does_not_exist.jsonl")) == []

    def test_skips_corrupted_lines_gracefully(self, log_path):
        with open(log_path, "w") as f:
            f.write('{"event_type": "attempt", "service": "SVC", "username": "u1"}\n')
            f.write("not valid json at all\n")
            f.write('{"event_type": "attempt", "service": "SVC", "username": "u2"}\n')

        events = read_events(log_path)
        assert len(events) == 2  # la ligne corrompue est ignorée, pas de crash


class TestSummarize:
    def test_summarize_counts_correctly(self, log_path):
        logger = AuditLogger(log_path)
        logger.log_campaign_start(service="SVC", protocol="smb", total_users=2)
        logger.log_attempt(service="SVC", username="user1", success=True)
        logger.log_attempt(service="SVC", username="user2", success=False)
        logger.log_lockout_detected(service="SVC", username="user2")

        summary = summarize(log_path)
        assert summary["total_campaigns"] == 1
        assert summary["total_attempts"] == 2
        assert summary["total_successes"] == 1
        assert summary["total_lockouts_detected"] == 1
        assert summary["services"] == ["SVC"]

    def test_summarize_empty_log(self, tmp_path):
        summary = summarize(str(tmp_path / "empty.jsonl"))
        assert summary["total_campaigns"] == 0
        assert summary["total_attempts"] == 0
