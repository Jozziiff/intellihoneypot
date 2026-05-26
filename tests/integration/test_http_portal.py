"""
Integration tests for the HTTP honeypot.

Requires a running stack (make up).
Run with: make test-integration
"""
import pytest
import httpx

BASE_URL = "http://localhost:8080"


@pytest.mark.asyncio
async def test_root_redirects_to_portal():
    async with httpx.AsyncClient(follow_redirects=True) as client:
        resp = await client.get(f"{BASE_URL}/")
    assert resp.status_code == 200
    assert "GlobalProtect" in resp.text


@pytest.mark.asyncio
async def test_login_page_renders():
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/global-protect/login.esp")
    assert resp.status_code == 200
    assert "Username" in resp.text or "username" in resp.text.lower()


@pytest.mark.asyncio
async def test_fake_headers_present():
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/global-protect/login.esp")
    assert resp.headers.get("server") == "Apache/2.4.41 (Ubuntu)"
    assert "PHP" in resp.headers.get("x-powered-by", "")


@pytest.mark.asyncio
async def test_credential_submission_returns_mfa():
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/global-protect/login.esp",
            data={"user": "admin", "passwd": "password123"},
        )
    assert resp.status_code == 200
    # Should show MFA challenge, not reject
    assert "verification" in resp.text.lower() or "mfa" in resp.text.lower() or "code" in resp.text.lower()


@pytest.mark.asyncio
async def test_scanner_path_returns_404():
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/phpmyadmin")
    assert resp.status_code == 404
    assert "Apache" in resp.text


@pytest.mark.asyncio
async def test_dotgit_returns_404():
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/.git/HEAD")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_prelogin_xml():
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{BASE_URL}/ssl-vpn/prelogin.esp")
    assert resp.status_code == 200
    assert "prelogin-response" in resp.text
