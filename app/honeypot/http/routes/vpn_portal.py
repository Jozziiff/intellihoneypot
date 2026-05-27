"""
Fake Palo Alto GlobalProtect VPN portal.

Why this persona? Enterprise VPN portals are high-value targets — they
attract sophisticated credential-harvesting attempts (rather than generic
WordPress scanners), which is the traffic worth analysing.

Endpoints we mimic:
    /                                  — redirect to login page
    /global-protect/login.esp          — login form (GET) + submit (POST)
    /ssl-vpn/prelogin.esp              — XML probed by the GlobalProtect client
    /global-protect/portal/prelogin.esp ↑ same as above (different path)
    /global-protect/portal/config.esp  — XML the client fetches after login
    /robots.txt                        — looks "professional"
    /global-protect/portal/css/login.css — the page's CSS

Every credential submission is captured and logged, then we return a fake
MFA challenge — never reject the login outright. Rejecting would tell the
attacker their password was wrong; we instead keep them busy with an
imaginary second factor.
"""
from __future__ import annotations

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.logging import get_logger
from app.session.manager import SessionManager
from app.session.models import AttackPhase, CapturedCredential, SessionEvent
from app.telemetry.event_logger import EventLogger

logger = get_logger(__name__)
router = APIRouter()

# XML payload the GlobalProtect client expects before showing the login page.
# Real-world value scraped from a public PAN-OS 9.1.3 portal.
_PRELOGIN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
  <status>Success</status>
  <ccusername/>
  <autosubmit>false</autosubmit>
  <msg/>
  <newmsg/>
  <authentication-message>Please enter your username and password</authentication-message>
  <username-label>Username</username-label>
  <password-label>Password</password-label>
  <panos-version>9.1.3</panos-version>
  <region>US</region>
</prelogin-response>"""

# XML the client fetches after a successful login — names a gateway it can
# connect to. The hostname is intentionally fake.
_PORTAL_CONFIG_XML = """<?xml version="1.0" encoding="UTF-8"?>
<policy>
  <version>8</version>
  <gateways>
    <external>
      <list>
        <entry name="acme-vpn-gw.acme.com">
          <priority>1</priority>
          <manual>0</manual>
        </entry>
      </list>
    </external>
  </gateways>
</policy>"""


def setup_vpn_router(
    templates: Jinja2Templates,
    session_mgr: SessionManager,
    event_logger: EventLogger,
) -> APIRouter:
    """
    Factory wires the SessionManager into closures.

    We use a closure pattern (instead of dependency injection) because
    FastAPI's startup is simple and a single-file router keeps grep easy.
    """

    @router.get("/", include_in_schema=False)
    async def root_redirect() -> RedirectResponse:
        return RedirectResponse(url="/global-protect/login.esp", status_code=302)

    @router.get("/global-protect/login.esp", include_in_schema=False)
    async def login_page(request: Request) -> HTMLResponse:
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        session = await session_mgr.create(client_ip, "http")
        session.user_agent = request.headers.get("user-agent", "")
        await session_mgr.update(session)

        await event_logger.log(
            session,
            "http_page_view",
            request.url.path,
            summary="HTTP honeypot page viewed",
        )

        return templates.TemplateResponse(request, "login.html")

    @router.post("/global-protect/login.esp", include_in_schema=False)
    async def login_submit(
        request: Request,
        # Real GlobalProtect uses `user`/`passwd`; many phishing-aware
        # tools use `username`/`password`. Accept either.
        user: str = Form(default=""),
        passwd: str = Form(default=""),
        username: str = Form(default=""),
        password: str = Form(default=""),
    ) -> HTMLResponse:
        final_user = user or username
        final_pass = passwd or password

        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )

        # New HTTP attackers get their own short-lived session — separate
        # from any SSH session even if the IP matches.
        session = await session_mgr.create(client_ip, "http")
        session.username = final_user
        session.user_agent = request.headers.get("user-agent", "")
        await session_mgr.update(session)

        if final_user or final_pass:
            cred = CapturedCredential(
                username=final_user,
                password=final_pass,
                service="http",
                method="form_submit",
            )
            await session_mgr.capture_credential(session.session_id, cred)

            event = SessionEvent(
                event_type="http_login_attempt",
                payload=f"user={final_user}",
                phase=AttackPhase.EXPLOITATION,
            )
            await session_mgr.append_event(session.session_id, event)

            await event_logger.log(
                session,
                "http_login_attempt",
                event.payload,
                summary="HTTP login attempt captured",
            )

            logger.warning(
                "http_credential_captured",
                ip=client_ip,
                username=final_user,
            )

        # ALWAYS pretend we need MFA — never accept/reject. This keeps the
        # attacker engaged and reveals whether they have a follow-up token
        # to try (which would be very interesting telemetry).
        return templates.TemplateResponse(
            request, "login.html", {"mfa_required": True, "username": final_user}
        )

    # The prelogin.esp endpoint lives under two paths in the wild —
    # match both so any GlobalProtect client variant works.
    @router.get("/ssl-vpn/prelogin.esp", include_in_schema=False)
    @router.post("/ssl-vpn/prelogin.esp", include_in_schema=False)
    @router.get("/global-protect/portal/prelogin.esp", include_in_schema=False)
    @router.post("/global-protect/portal/prelogin.esp", include_in_schema=False)
    async def prelogin(request: Request) -> Response:
        return Response(content=_PRELOGIN_XML, media_type="application/xml")

    @router.get("/global-protect/portal/config.esp", include_in_schema=False)
    @router.post("/global-protect/portal/config.esp", include_in_schema=False)
    async def portal_config(request: Request) -> Response:
        return Response(content=_PORTAL_CONFIG_XML, media_type="application/xml")

    @router.get("/robots.txt", include_in_schema=False)
    async def robots_txt() -> PlainTextResponse:
        # "Disallow" lines that look like they're hiding something — bait
        # for opportunistic scanners reading robots.txt.
        return PlainTextResponse(
            "User-agent: *\nDisallow: /global-protect/\nDisallow: /ssl-vpn/\n"
        )

    @router.get(
        "/global-protect/portal/css/login.css", include_in_schema=False
    )
    async def portal_css() -> Response:
        css = """
body{margin:0;font-family:Arial,sans-serif;background:#1a2332}
.login-container{width:400px;margin:80px auto;background:#fff;border-radius:4px;padding:40px}
.logo{text-align:center;margin-bottom:30px}
input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:3px;box-sizing:border-box}
button{width:100%;padding:12px;background:#0070d1;color:white;border:none;border-radius:3px;cursor:pointer}
"""
        return Response(content=css, media_type="text/css")

    return router
