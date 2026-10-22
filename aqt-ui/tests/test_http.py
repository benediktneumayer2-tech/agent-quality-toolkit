"""HTTP layer: login, session cookie, Host check, CSRF and Origin, headers, logging."""

from aqt_ui.server import CSP


def test_no_cookie_is_refused(trail, ui_factory):
    client = ui_factory()
    status, data, _ = client.get("/api/overview")
    assert status == 401 and data["ok"] is False
    status, body, response = client.get("/")
    assert status == 401 and b"login link" in body.lower()
    assert response.getheader("Content-Security-Policy") == CSP


def test_login_link_works_once_and_sets_a_strict_cookie(trail, ui_factory):
    client = ui_factory()
    link = client.app.new_login_link()
    path = link.split(str(client.port), 1)[1]
    response, _ = client.request("GET", path)
    assert response.status == 303 and response.getheader("Location") == "/"
    cookie = response.getheader("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    assert "Expires" not in cookie and "Max-Age" not in cookie
    again, _ = client.request("GET", path)
    assert again.status == 403
    bogus, _ = client.request("GET", "/login?t=not-a-token")
    assert bogus.status == 403


def test_pages_and_api_with_a_session(trail, ui_factory):
    client = ui_factory()
    client.login()
    for page in ("/", "/trail", "/quarantine", "/changes", "/signatures", "/capa", "/qualifications"):
        status, body, response = client.get(page)
        assert status == 200 and b'<script type="module" src="/static/app.js">' in body
        assert response.getheader("Content-Security-Policy") == CSP
        assert response.getheader("X-Frame-Options") == "DENY"
    status, data, response = client.get("/api/overview")
    assert status == 200 and "needs" in data
    assert response.getheader("Cache-Control") == "no-store"
    assert response.getheader("Referrer-Policy") == "no-referrer"
    assert response.getheader("X-Content-Type-Options") == "nosniff"


def test_foreign_host_header_is_refused(trail, ui_factory):
    client = ui_factory()
    client.login()
    status, _, _ = client.get("/api/overview", host=f"evil.example:{client.port}")
    assert status == 403
    status, _, _ = client.get("/api/overview", host="127.0.0.1:1")
    assert status == 403
    status, _, _ = client.get("/api/overview", host=f"localhost:{client.port}")
    assert status == 200


def test_state_changes_need_csrf_header_and_origin(trail, ui_factory):
    client = ui_factory()
    client.login()
    status, data, _ = client.post("/api/trail/verify", csrf=False)
    assert status == 403 and "CSRF" in data["message"]
    status, data, _ = client.post("/api/trail/verify", origin=False)
    assert status == 403 and "Origin" in data["message"]
    status, data, _ = client.post("/api/trail/verify", headers={"Origin": "http://evil.example"})
    assert status == 403 and "Origin" in data["message"]
    status, data, _ = client.post("/api/trail/verify", headers={"X-AQT-CSRF": "wrong"})
    assert status == 403
    status, data, _ = client.post("/api/trail/verify", headers={"Content-Type": "text/plain"})
    assert status == 403
    status, data, _ = client.post("/api/trail/verify")
    assert status == 202 and data["ok"]


def test_cookie_of_another_session_does_not_work(trail, ui_factory):
    first, second = ui_factory(), ui_factory()
    first.login()
    second.cookie = first.cookie.replace(first.app.cookie_name, second.app.cookie_name)
    status, _, _ = second.get("/api/overview")
    assert status == 401


def test_log_has_no_query_strings(trail, ui_factory):
    client = ui_factory()
    client.login()
    client.get("/api/trail/records?actor=human:secret-filter")
    assert client.log, "requests are logged"
    assert all("?" not in line and "secret-filter" not in line for line in client.log)
    assert all("login?t=" not in line for line in client.log)


def test_static_files_and_unknown_paths(trail, ui_factory):
    client = ui_factory()
    status, body, response = client.get("/static/app.js")
    assert status == 200 and response.getheader("Content-Type").startswith("text/javascript")
    assert b"innerHTML" not in body          # data is never put into the page as markup
    status, _, _ = client.get("/static/../server.py")
    assert status == 404
    client.login()
    status, _, _ = client.get("/api/nothing")
    assert status == 404
