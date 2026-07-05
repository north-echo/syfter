"""Integration tests for SBOM export endpoints."""

import pytest

pytestmark = pytest.mark.integration


class TestGetSBOM:
    def test_get_sbom_default_format(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/export/{name}/{version}")
        assert resp.status_code == 200

    def test_get_sbom_syft_json(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/export/{name}/{version}",
            params={"format": "syft-json"},
        )
        assert resp.status_code == 200

    def test_get_sbom_nonexistent_product(self, api):
        resp = api.get("/api/v1/export/nonexistent/0.0")
        assert resp.status_code == 404


class TestGetSBOMUrl:
    def test_get_sbom_url(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/export/{name}/{version}/url")
        assert resp.status_code == 200
        data = resp.json()
        assert "url" in data or "download_url" in data or isinstance(data, str)

    def test_get_sbom_url_custom_expiry(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/export/{name}/{version}/url",
            params={"expires_in": 600},
        )
        assert resp.status_code == 200

    def test_get_sbom_url_nonexistent_product(self, api):
        resp = api.get("/api/v1/export/nonexistent/0.0/url")
        assert resp.status_code == 404
