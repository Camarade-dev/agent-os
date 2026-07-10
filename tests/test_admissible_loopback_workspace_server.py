import http.client
import os
import sys
from urllib.parse import urlsplit

import pytest

from admissible.browser_runtime.server import (
    LoopbackWorkspaceServer,
    WorkspaceTraversalError,
    resolve_workspace_request_path,
)


@pytest.fixture()
def workspace(tmp_path):
    (tmp_path / "index.html").write_text("<h1>hi</h1>", encoding="utf-8")
    (tmp_path / "style.css").write_text("body{}", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.js").write_text("// nested", encoding="utf-8")
    admissible_dir = tmp_path / ".admissible"
    admissible_dir.mkdir()
    (admissible_dir / "secret.json").write_text("{}", encoding="utf-8")
    outside = tmp_path.parent / "outside_secret.txt"
    outside.write_text("outside", encoding="utf-8")
    yield tmp_path


@pytest.fixture()
def server(workspace):
    srv = LoopbackWorkspaceServer(workspace)
    srv.start()
    yield srv
    srv.stop()


def _get(server, path, *, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    conn.request(method, path, headers={"Host": f"127.0.0.1:{server.server_address[1]}"})
    response = conn.getresponse()
    body = response.read()
    conn.close()
    return response, body


def test_server_binds_only_to_loopback(server):
    host = server.server_address[0]
    assert host in ("127.0.0.1", "0.0.0.0") is False or host == "127.0.0.1"
    assert host == "127.0.0.1"


def test_get_and_head_work_for_authorized_files(server):
    response, body = _get(server, f"/{server.token}/index.html")
    assert response.status == 200
    assert b"hi" in body
    assert response.getheader("Content-Security-Policy")

    response2, body2 = _get(server, f"/{server.token}/index.html", method="HEAD")
    assert response2.status == 200
    assert body2 == b""


def test_root_token_serves_index(server):
    response, body = _get(server, f"/{server.token}/")
    assert response.status == 200
    assert b"hi" in body


def test_missing_token_is_rejected(server):
    response, _ = _get(server, "/index.html")
    assert response.status == 404


def test_path_traversal_is_rejected(server):
    response, _ = _get(server, f"/{server.token}/../outside_secret.txt")
    assert response.status in (403, 404)


def test_encoded_traversal_is_rejected(server):
    response, _ = _get(server, f"/{server.token}/%2e%2e/outside_secret.txt")
    assert response.status in (403, 404)


def test_backslash_alternate_separator_is_rejected(server):
    response, _ = _get(server, f"/{server.token}/..%5coutside_secret.txt")
    assert response.status in (403, 404)


def test_hidden_admissible_state_is_not_served(server):
    response, _ = _get(server, f"/{server.token}/.admissible/secret.json")
    assert response.status == 403


def test_unsupported_http_methods_are_rejected(server):
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        response, _ = _get(server, f"/{server.token}/index.html", method=method)
        assert response.status == 405


def test_nested_authorized_file_is_served(server):
    response, body = _get(server, f"/{server.token}/sub/nested.js")
    assert response.status == 200
    assert b"nested" in body
    assert "javascript" in response.getheader("Content-Type")


def test_resolve_workspace_request_path_rejects_traversal(workspace):
    with pytest.raises(WorkspaceTraversalError):
        resolve_workspace_request_path(workspace, "../outside_secret.txt")


def test_resolve_workspace_request_path_rejects_hidden_admissible_state(workspace):
    with pytest.raises(WorkspaceTraversalError):
        resolve_workspace_request_path(workspace, ".admissible/secret.json")


@pytest.mark.skipif(sys.platform.startswith("win") and os.environ.get("CI") is None, reason="symlink creation may require elevated privileges on Windows")
def test_symlink_escape_is_rejected(workspace):
    link = workspace / "escape_link"
    target = workspace.parent / "outside_secret.txt"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("symlink creation not permitted in this environment")
    with pytest.raises(WorkspaceTraversalError):
        resolve_workspace_request_path(workspace, "escape_link")


def test_request_log_is_retained_as_evidence(server):
    _get(server, f"/{server.token}/index.html")
    _get(server, f"/{server.token}/missing.html")
    assert len(server.request_log) >= 2
    assert any(entry["status"] == 200 for entry in server.request_log)
    assert any(entry["status"] == 404 for entry in server.request_log)


def test_server_url_for_builds_token_scoped_urls(server):
    url = server.url_for("index.html", "debug=1")
    parts = urlsplit(url)
    assert parts.hostname == "127.0.0.1"
    assert parts.path == f"/{server.token}/index.html"
    assert parts.query == "debug=1"
