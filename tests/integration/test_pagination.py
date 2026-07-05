"""Integration tests for pagination behavior across endpoints."""

import pytest

pytestmark = pytest.mark.integration

PAGINATED_ENDPOINTS = [
    "/api/v1/products/",
    "/api/v1/systems/",
    "/api/v1/scans/",
    "/api/v1/query/packages",
    "/api/v1/query/files",
    "/api/v1/query/dependencies",
    "/api/v1/query/components",
    "/api/v1/relationships/",
]


class TestPaginationDefaults:
    @pytest.mark.parametrize("endpoint", PAGINATED_ENDPOINTS)
    def test_default_limit_returns_at_most_100(self, api, endpoint):
        resp = api.get(endpoint)
        assert resp.status_code == 200
        assert len(resp.json()) <= 100


class TestPaginationLimit:
    @pytest.mark.parametrize("endpoint", PAGINATED_ENDPOINTS)
    def test_limit_1(self, api, endpoint):
        resp = api.get(endpoint, params={"limit": 1})
        assert resp.status_code == 200
        assert len(resp.json()) <= 1

    @pytest.mark.parametrize("endpoint", PAGINATED_ENDPOINTS)
    def test_limit_0_returns_empty_or_rejects(self, api, endpoint):
        resp = api.get(endpoint, params={"limit": 0})
        assert resp.status_code in (200, 422)
        if resp.status_code == 200:
            assert resp.json() == []


class TestPaginationOffset:
    def test_offset_produces_different_results(self, api):
        page1 = api.get("/api/v1/products/", params={"limit": 1, "offset": 0})
        page2 = api.get("/api/v1/products/", params={"limit": 1, "offset": 1})
        assert page1.status_code == 200
        assert page2.status_code == 200
        if page1.json() and page2.json():
            assert page1.json()[0]["id"] != page2.json()[0]["id"]

    def test_large_offset_returns_empty(self, api):
        resp = api.get(
            "/api/v1/products/", params={"limit": 10, "offset": 999999}
        )
        assert resp.status_code == 200
        assert resp.json() == []


class TestHighLimitEndpoints:
    """Endpoints with higher max limits (list/packages, list/files)."""

    def test_list_packages_high_limit(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/query/list/packages/{name}/{version}",
            params={"limit": 10000},
        )
        assert resp.status_code == 200

    def test_list_files_high_limit(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/query/list/files/{name}/{version}",
            params={"limit": 10000},
        )
        assert resp.status_code == 200
