"""
Empirical Lockout Discovery - Module 1bis
============================================

Objectif : mesurer la vraie politique de lockout par test contrôlé, pour
les cas où la lecture LDAP directe (Module 1 / discovery.py) échoue —
ACL restrictive, dsHeuristics désactivant le bind anonyme, AD durci.

Principe :
  1. Vérifie que le compte de test n'est pas déjà verrouillé
  2. Enchaîne des binds avec un mauvais mot de passe, un par un, avec délai
  3. Parse le sous-code d'erreur AD ("data 775" = compte verrouillé,
     documented Microsoft LDAP bind error sub-codes) après chaque échec
  4. threshold = nombre d'échecs qui ont précédé le verrouillage détecté
  5. Optionnel : mesure la durée réelle du verrouillage en réessayant le
     bon mot de passe périodiquement jusqu'à succès

ATTENTION — CE TEST VERROUILLE DÉLIBÉRÉMENT UN COMPTE :
  - À utiliser UNIQUEMENT sur un compte de test jetable fourni explicitement
    par le client pour cet usage (jamais un compte de production/utilisateur réel)
  - Le verrouillage résultant est un effet secondaire ATTENDU et VOULU de la
    mesure, pas un bug — c'est ce qui permet de déterminer le seuil réel
  - `max_attempts` est plafonné à 20 par sécurité (voir __init__)

Dépendance : pip install ldap3
"""

import re
import time
from typing import Optional

from ldap3 import Server, Connection, SIMPLE
from ldap3.core.exceptions import LDAPException

# Sous-codes d'erreur AD embarqués dans le message de bind LDAP échoué
# (documentés par Microsoft : "AcceptSecurityContext error, data XXX")
AD_DATA_CODES = {
    "525": "user_not_found",
    "52e": "invalid_credentials",
    "530": "not_permitted_at_this_time",
    "531": "not_permitted_to_this_workstation",
    "532": "password_expired",
    "533": "account_disabled",
    "701": "account_expired",
    "773": "must_reset_password",
    "775": "account_locked",
}

MAX_ATTEMPTS_HARD_CAP = 20


def _extract_ad_data_code(message: str) -> Optional[str]:
    if not message:
        return None
    match = re.search(r"data (\w+),", message)
    return match.group(1) if match else None


class EmpiricalLockoutDiscovery:
    def __init__(self, dc_ip: str, test_username: str, correct_password: str,
                 use_ssl: bool = False, max_attempts: int = 10,
                 delay_between_attempts: float = 2.0):
        """
        dc_ip               : IP/hostname du Domain Controller
        test_username        : compte de test JETABLE (jamais un compte réel)
        correct_password     : mot de passe correct connu de ce compte
        max_attempts          : plafond d'essais avant abandon (défaut 10,
                                 refusé au-delà de 20 par sécurité)
        delay_between_attempts : pause entre chaque essai, pour rester
                                  raisonnable vis-à-vis du DC/SOC
        """
        if not dc_ip or not dc_ip.strip():
            raise ValueError("dc_ip ne peut pas être vide")
        if not test_username or not correct_password:
            raise ValueError("test_username et correct_password sont requis")
        if max_attempts > MAX_ATTEMPTS_HARD_CAP:
            raise ValueError(
                f"max_attempts > {MAX_ATTEMPTS_HARD_CAP} refusé par sécurité "
                "(risque de verrouillage prolongé ou de comportement anormal côté AD)"
            )
        if max_attempts < 1:
            raise ValueError("max_attempts doit être >= 1")

        self.dc_ip = dc_ip
        self.test_username = test_username
        self.correct_password = correct_password
        self.use_ssl = use_ssl
        self.max_attempts = max_attempts
        self.delay_between_attempts = delay_between_attempts

        if not use_ssl:
            print("[!] ATTENTION : test empirique sans use_ssl=True — le mot de passe "
                  "du compte de test transitera EN CLAIR sur le réseau à chaque essai.")

    def _try_bind(self, password: str) -> tuple[bool, Optional[str]]:
        """Retourne (success, ad_data_code). Une connexion neuve par essai
        (nécessaire : un Connection ldap3 ne peut pas re-bind proprement
        après un échec dans tous les cas)."""
        server = Server(self.dc_ip, use_ssl=self.use_ssl)
        conn = Connection(server, user=self.test_username, password=password,
                           authentication=SIMPLE, raise_exceptions=False)
        try:
            success = conn.bind()
        except LDAPException as e:
            return False, _extract_ad_data_code(str(e))

        code = None
        if not success:
            code = _extract_ad_data_code(conn.result.get("message", ""))

        try:
            conn.unbind()
        except LDAPException:
            pass

        return success, code

    def verify_account_not_locked(self) -> bool:
        """Pré-check indispensable : si le compte est déjà verrouillé avant
        même de commencer, toute la mesure serait faussée."""
        success, code = self._try_bind(self.correct_password)
        if not success:
            reason = AD_DATA_CODES.get(code, code or "raison inconnue")
            print(f"[!] Le compte de test est déjà inaccessible avant le test "
                  f"({reason}). Vérifie qu'il n'est pas déjà verrouillé/mal configuré, "
                  "ou fournis un autre compte de test.")
        return success

    def measure_threshold(self) -> Optional[int]:
        """Retourne le nombre d'échecs qui ont précédé le verrouillage
        détecté, ou None si aucun verrouillage constaté avant max_attempts."""
        wrong_password = self.correct_password + "_sprayctl_wrong_test"

        for attempt in range(1, self.max_attempts + 1):
            success, code = self._try_bind(wrong_password)

            if success:
                # ne devrait jamais arriver vu le mot de passe volontairement altéré
                print("[!] Anomalie : bind réussi avec un mot de passe volontairement "
                      "incorrect — arrêt de la mesure, résultat non fiable.")
                return None

            if code == "775":
                print(f"[+] Verrouillage détecté après {attempt} échec(s).")
                return attempt

            time.sleep(self.delay_between_attempts)

        print(f"[i] Pas de verrouillage constaté après {self.max_attempts} échecs — "
              "seuil probablement élevé, policy désactivée, ou détection différente "
              "(Smart Lockout non classique). Fallback prudent recommandé.")
        return None

    def measure_lockout_duration_minutes(self, poll_interval_seconds: float = 30.0,
                                          max_wait_minutes: float = 60.0) -> Optional[float]:
        """À appeler après un measure_threshold() ayant confirmé un
        verrouillage. Réessaie le bon mot de passe périodiquement jusqu'à
        succès, pour mesurer la durée réelle du verrouillage.

        Utilisé comme approximation de window_minutes (conservateur : la
        fenêtre d'observation est généralement <= à la durée de lockout
        sur une config AD par défaut, donc utiliser la durée mesurée comme
        fenêtre reste prudent plutôt qu'optimiste).
        """
        start = time.monotonic()
        max_wait_seconds = max_wait_minutes * 60

        while (time.monotonic() - start) < max_wait_seconds:
            success, _ = self._try_bind(self.correct_password)
            if success:
                elapsed_minutes = (time.monotonic() - start) / 60
                print(f"[+] Compte déverrouillé après ~{elapsed_minutes:.1f} minutes.")
                return elapsed_minutes
            time.sleep(poll_interval_seconds)

        print(f"[!] Toujours verrouillé après {max_wait_minutes:.0f} minutes — "
              "déverrouillage probablement manuel (admin) uniquement.")
        return None

    def run_full_measurement(self, measure_duration: bool = False) -> dict:
        """Point d'entrée haut niveau, retourne un dict prêt pour
        orch.set_policy(service, **kwargs).

        measure_duration=True rallonge fortement le test (jusqu'à
        max_wait_minutes) — à activer seulement si le temps de mission le
        permet et que la précision de la fenêtre importe vraiment.
        """
        if not self.verify_account_not_locked():
            return {"threshold": 3, "window_minutes": 15.0}

        threshold = self.measure_threshold()
        if threshold is None:
            return {"threshold": 10, "window_minutes": 30.0}

        result = {"threshold": threshold, "window_minutes": 30.0}

        if measure_duration:
            duration = self.measure_lockout_duration_minutes()
            if duration is not None:
                result["window_minutes"] = duration

        return result


if __name__ == "__main__":
    # Exemple — nécessite un compte de test JETABLE fourni par le client
    discovery = EmpiricalLockoutDiscovery(
        dc_ip="10.10.10.10",
        test_username="test.spray@corp.local",
        correct_password="CorrectTestPassword123!",
        max_attempts=10,
        delay_between_attempts=2.0,
    )
    kwargs = discovery.run_full_measurement(measure_duration=False)
    print(kwargs)
