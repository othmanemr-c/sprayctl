"""
Lockout Policy Discovery - Module 1
=====================================

Objectif : récupérer la vraie politique de lockout AD (threshold, window,
duration) via LDAP, pour alimenter automatiquement le SprayOrchestrator
(Module 2/3) au lieu de deviner ces valeurs à la main.

Deux sources possibles, dans l'ordre de préférence :
  1. Fine-Grained Password Policies (msDS-PasswordSettings) — si elles
     existent et sont lisibles, elles priment sur la policy par défaut
     et peuvent différer par groupe/OU.
  2. Domain default password policy (attributs sur l'objet domaine :
     lockoutThreshold, lockoutDuration, lockOutObservationWindow).

Pré-requis : un bind LDAP, même en anonyme ou en low-priv. Sur beaucoup
d'AD internes, une lecture anonyme du domain root suffit pour lire la
policy par défaut (souvent pas ACL-restreinte). Les FGPP nécessitent en
général un compte authentifié avec droits de lecture sur le conteneur
Password Settings Container.

Dépendance : pip install ldap3
"""

from dataclasses import dataclass
from typing import Optional

from ldap3 import Server, Connection, ALL, ANONYMOUS, SIMPLE, SUBTREE
from ldap3.core.exceptions import LDAPException


# AD stocke les durées en "intervalles négatifs de 100-nanosecondes".
# Conversion : valeur / -10_000_000 = secondes.
def _ad_interval_to_minutes(raw_value: int) -> float:
    if raw_value == 0:
        return 0.0
    return abs(raw_value) / 10_000_000 / 60


@dataclass
class DiscoveredPolicy:
    source: str                 # "default" ou "fgpp:<nom_de_la_policy>"
    threshold: int               # lockoutThreshold
    window_minutes: float        # lockOutObservationWindow
    duration_minutes: float      # lockoutDuration (0 = lockout jusqu'à déblocage admin)
    applies_to: Optional[str] = None  # DN du groupe/user ciblé si FGPP

    def is_lockout_disabled(self) -> bool:
        return self.threshold == 0


class LockoutPolicyDiscovery:
    def __init__(self, dc_ip: str, domain_dn: str,
                 username: Optional[str] = None, password: Optional[str] = None,
                 use_ssl: bool = False):
        """
        dc_ip       : IP ou hostname d'un Domain Controller
        domain_dn   : DN du domaine, ex: "DC=corp,DC=local"
        username    : "DOMAIN\\user" ou UPN — laisser None pour tenter un bind anonyme
        password    : mot de passe associé

        SÉCURITÉ : si username/password sont fournis avec use_ssl=False, le
        bind LDAP "simple" envoie les credentials EN CLAIR sur le réseau
        (pas de STARTTLS ici). À réserver aux labs/segments de confiance ou
        à activer use_ssl=True (LDAPS, port 636) en conditions réelles.
        """
        if not dc_ip or not dc_ip.strip():
            raise ValueError("dc_ip ne peut pas être vide")
        if not domain_dn or not domain_dn.strip():
            raise ValueError("domain_dn ne peut pas être vide")

        self.dc_ip = dc_ip
        self.domain_dn = domain_dn
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self._conn: Optional[Connection] = None

        if username and not use_ssl:
            print("[!] ATTENTION : bind authentifié sans use_ssl=True — "
                  "le mot de passe transitera EN CLAIR sur le réseau (LDAP simple bind). "
                  "Utilise use_ssl=True (LDAPS) hors environnement de lab.")

    # ------------------------------------------------------------------ #
    # Connexion
    # ------------------------------------------------------------------ #

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self) -> bool:
        server = Server(self.dc_ip, use_ssl=self.use_ssl, get_info=ALL)
        try:
            if self.username:
                self._conn = Connection(
                    server, user=self.username, password=self.password,
                    authentication=SIMPLE, auto_bind=True,
                )
            else:
                self._conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
            return True
        except LDAPException as e:
            print(f"[!] Échec du bind LDAP ({'auth' if self.username else 'anonyme'}) : {e}")
            self._conn = None
            return False

    def close(self):
        if self._conn:
            try:
                self._conn.unbind()
            except LDAPException:
                pass  # meilleure tentative — on ne bloque pas la fermeture
            finally:
                self._conn = None

    # ------------------------------------------------------------------ #
    # Default domain policy
    # ------------------------------------------------------------------ #

    def get_default_policy(self) -> Optional[DiscoveredPolicy]:
        if not self._conn:
            raise RuntimeError("Appelle connect() avant.")

        attrs = ["lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"]
        try:
            self._conn.search(
                search_base=self.domain_dn,
                search_filter="(objectClass=domain)",
                search_scope=SUBTREE,
                attributes=attrs,
            )
        except LDAPException as e:
            print(f"[!] Erreur de recherche LDAP sur la policy par défaut : {e}")
            return None

        if not self._conn.entries:
            print("[!] Impossible de lire l'objet domaine — droits insuffisants ou DN incorrect")
            return None

        entry = self._conn.entries[0]
        threshold = int(entry["lockoutThreshold"].value or 0)
        duration_raw = int(entry["lockoutDuration"].value or 0)
        window_raw = int(entry["lockOutObservationWindow"].value or 0)

        return DiscoveredPolicy(
            source="default",
            threshold=threshold,
            window_minutes=_ad_interval_to_minutes(window_raw),
            duration_minutes=_ad_interval_to_minutes(duration_raw),
        )

    # ------------------------------------------------------------------ #
    # Fine-Grained Password Policies (PSO)
    # ------------------------------------------------------------------ #

    def get_fine_grained_policies(self) -> list[DiscoveredPolicy]:
        """Cherche dans CN=Password Settings Container,CN=System,<domain_dn>.
        Retourne une liste vide si non lisible ou inexistant (normal sur
        beaucoup d'AD qui n'utilisent que la policy par défaut).
        """
        if not self._conn:
            raise RuntimeError("Appelle connect() avant.")

        psc_dn = f"CN=Password Settings Container,CN=System,{self.domain_dn}"
        attrs = [
            "msDS-LockoutThreshold",
            "msDS-LockoutObservationWindow",
            "msDS-LockoutDuration",
            "msDS-PSOAppliesTo",
            "cn",
        ]

        try:
            self._conn.search(
                search_base=psc_dn,
                search_filter="(objectClass=msDS-PasswordSettings)",
                search_scope=SUBTREE,
                attributes=attrs,
            )
        except LDAPException as e:
            print(f"[i] Password Settings Container non accessible ({e}) — normal si pas de FGPP configurée")
            return []

        results = []
        for entry in self._conn.entries:
            threshold = int(entry["msDS-LockoutThreshold"].value or 0)
            window_raw = int(entry["msDS-LockoutObservationWindow"].value or 0)
            duration_raw = int(entry["msDS-LockoutDuration"].value or 0)
            applies_to = None
            if "msDS-PSOAppliesTo" in entry and entry["msDS-PSOAppliesTo"].value:
                applies_to = str(entry["msDS-PSOAppliesTo"].value)

            results.append(DiscoveredPolicy(
                source=f"fgpp:{entry['cn'].value}",
                threshold=threshold,
                window_minutes=_ad_interval_to_minutes(window_raw),
                duration_minutes=_ad_interval_to_minutes(duration_raw),
                applies_to=applies_to,
            ))
        return results

    # ------------------------------------------------------------------ #
    # API haut niveau
    # ------------------------------------------------------------------ #

    def discover_most_restrictive(self) -> Optional[DiscoveredPolicy]:
        """Retourne la policy la plus stricte trouvée (défaut + FGPP),
        celle qu'il faut respecter par sécurité si on ne peut pas
        déterminer précisément quel user est couvert par quelle FGPP.
        """
        candidates = []

        default = self.get_default_policy()
        if default and not default.is_lockout_disabled():
            candidates.append(default)

        for pso in self.get_fine_grained_policies():
            if not pso.is_lockout_disabled():
                candidates.append(pso)

        if not candidates:
            return None

        # La plus restrictive = le threshold le plus bas
        return min(candidates, key=lambda p: p.threshold)


# ---------------------------------------------------------------------- #
# Exemple d'utilisation — branchement direct sur le SprayOrchestrator
# ---------------------------------------------------------------------- #

def build_orchestrator_policy_from_ad(dc_ip: str, domain_dn: str,
                                        username: Optional[str] = None,
                                        password: Optional[str] = None) -> dict:
    """Retourne un dict prêt à passer à orch.set_policy(service, **kwargs)."""
    with LockoutPolicyDiscovery(dc_ip, domain_dn, username, password) as discovery:
        if discovery._conn is None:
            print("[!] Discovery impossible — fallback recommandé : valeurs prudentes par défaut (threshold=3, window=15min)")
            return {"threshold": 3, "window_minutes": 15.0}

        policy = discovery.discover_most_restrictive()

        if policy is None:
            print("[i] Aucune politique de lockout active détectée (ou lecture impossible) — prudence maximale recommandée")
            return {"threshold": 3, "window_minutes": 15.0}

        print(f"[+] Politique retenue : source={policy.source}, threshold={policy.threshold}, "
              f"window={policy.window_minutes:.1f}min, duration={policy.duration_minutes:.1f}min")

        return {"threshold": policy.threshold, "window_minutes": policy.window_minutes}


if __name__ == "__main__":
    # Exemple : bind anonyme sur un DC pour lire la policy par défaut
    kwargs = build_orchestrator_policy_from_ad(
        dc_ip="10.10.10.10",
        domain_dn="DC=corp,DC=local",
    )
    print(kwargs)

    # Branchement direct :
    # from spray_orchestrator import SprayOrchestrator
    # orch = SprayOrchestrator("campaign.db")
    # orch.set_policy("CORP-AD", **kwargs, safety_margin=0.8)
