"""Integration tests for root and health endpoints."""

import pytest

pytestmark = pytest.mark.integration


class TestRoot:
    def test_root_returns_api_info(self, api):
        resp = api.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert "name" in data or "version" in data or "title" in data

    def test_health_returns_ok(self, api):
        resp = api.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "ok" or "status" in data


class TestOpenAPI:
    def test_openapi_json_available(self, api):
        resp = api.get("/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec

    def test_docs_endpoint(self, api):
        resp = api.get("/docs")
        assert resp.status_code == 200
