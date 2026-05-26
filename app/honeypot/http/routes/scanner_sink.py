"""
Catch-all "scanner sink" routes.

Web scanners (Nikto, Dirb, gobuster, …) hammer a server with hundreds of
guesses like `/wp-admin`, `/.git/config`, `/phpinfo.php`. A real server
returns 404s for unknown paths; a misconfigured app server crashes.
We return believable Apache-style 404s/403s so scanners think they found
"a real server with nothing exposed", and we log every probe.

Three response classes:
  * `_FORBIDDEN_PATHS` → 403 (the file "exists but is access-controlled").
  * `_LURE_PATHS`      → 200 with bait content (e.g. fake `/.env`).
  * Everything else    → 404 Not Found.
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Verbatim Apache 2.4 error page templates — chosen to fingerprint as Apache.
_APACHE_404 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL {path} was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at {host} Port 80</address>
</body></html>"""

_APACHE_403 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at {host} Port 80</address>
</body></html>"""

# Paths that exist but are access-controlled — scanners interpret 403 as
# "there IS something here, just hidden" and may retry with auth.
_FORBIDDEN_PATHS = {
    "/.htpasswd",
    "/.htaccess",
    "/config.php",
    "/web.config",
    "/db.sql",
    "/database.sql",
    "/backup.zip",
    "/backup.tar.gz",
}

# Paths that return believable lure content. Each value is (media_type, body).
# Goal: convince the scanner they found something juicy so they keep probing.
_LURE_PATHS: dict[str, tuple[str, str]] = {
    "/phpinfo.php": ("text/html", "<html><body>PHP Version 7.4.3</body></html>"),
    "/info.php": ("text/html", "<html><body>PHP Version 7.4.3</body></html>"),
    "/.env": ("text/plain", "APP_ENV=production\nDB_PASSWORD=\nAPP_KEY=\n"),
}


@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"],
)
async def catch_all(request: Request, path: str) -> HTMLResponse:
    full_path = f"/{path}"
    host = request.headers.get("host", "localhost")

    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )

    logger.info(
        "scanner_probe",
        ip=client_ip,
        path=full_path,
        method=request.method,
        ua=request.headers.get("user-agent", ""),
    )

    if full_path in _FORBIDDEN_PATHS:
        return HTMLResponse(
            content=_APACHE_403.format(host=host),
            status_code=403,
        )

    if full_path in _LURE_PATHS:
        media_type, content = _LURE_PATHS[full_path]
        return HTMLResponse(content=content, status_code=200, media_type=media_type)

    return HTMLResponse(
        content=_APACHE_404.format(path=full_path, host=host),
        status_code=404,
    )
