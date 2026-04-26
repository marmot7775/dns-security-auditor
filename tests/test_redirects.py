import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from server import app

client = TestClient(app)


def test_methodology_redirects_to_about():
    response = client.get("/methodology", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == "/about"


def test_methodology_redirect_chain_resolves():
    response = client.get("/methodology", follow_redirects=True)
    assert response.status_code == 200
    body = response.content.lower()
    assert b"about" in body or b"dns-audit" in body
