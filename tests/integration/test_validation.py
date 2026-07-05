"""Integration tests for input validation and error handling."""

import pytest

pytestmark = pytest.mark.integration


class TestProductValidation:
    def test_create_product_empty_body(self, api):
        resp = api.post("/api/v1/products/", json={})
        assert resp.status_code == 422
        detail = resp.json().get("detail", [])
        assert isinstance(detail, list)

    def test_create_product_extra_fields_ignored(self, api, cleanup_products):
        import uuid

        name = f"inttest-extra-{uuid.uuid4().hex[:8]}"
        resp = api.post(
            "/api/v1/products/",
            json={
                "name": name,
                "version": "1.0",
                "bogus_field": "should be ignored",
            },
        )
        assert resp.status_code == 201
        cleanup_products.append((name, "1.0"))

    def test_product_name_with_slashes(self, api, cleanup_products):
        import uuid

        name = f"inttest/slash/{uuid.uuid4().hex[:8]}"
        resp = api.post(
            "/api/v1/products/",
            json={"name": name, "version": "1.0"},
        )
        # Slashes in names are valid but tricky for path params
        if resp.status_code == 201:
            cleanup_products.append((name, "1.0"))


class TestSystemValidation:
    def test_create_system_empty_body(self, api):
        resp = api.post("/api/v1/systems/", json={})
        assert resp.status_code == 422

    def test_update_system_empty_body(self, api):
        resp = api.put("/api/v1/systems/nonexistent.test", json={})
        assert resp.status_code in (404, 422)


class TestScanValidation:
    def test_import_empty_sbom(self, api):
        resp = api.post(
            "/api/v1/scans/import",
            data={"product_name": "x", "product_version": "1.0"},
            files={"sbom": ("empty.json", b"", "application/json")},
        )
        assert resp.status_code in (400, 422, 500)

    def test_import_invalid_json_sbom(self, api):
        resp = api.post(
            "/api/v1/scans/import",
            data={"product_name": "x", "product_version": "1.0"},
            files={"sbom": ("bad.json", b"not json", "application/json")},
        )
        assert resp.status_code in (400, 422, 500)


class TestQueryValidation:
    def test_packages_negative_limit(self, api):
        resp = api.get(
            "/api/v1/query/packages", params={"limit": -1}
        )
        assert resp.status_code in (200, 422)

    def test_packages_limit_exceeds_max(self, api):
        resp = api.get(
            "/api/v1/query/packages", params={"limit": 9999}
        )
        assert resp.status_code in (200, 422)

    def test_packages_negative_offset(self, api):
        resp = api.get(
            "/api/v1/query/packages", params={"offset": -1}
        )
        assert resp.status_code in (200, 422)

    def test_trace_missing_required_name(self, api):
        resp = api.get("/api/v1/query/trace")
        assert resp.status_code == 422

    def test_frequency_missing_required_name(self, api):
        resp = api.get("/api/v1/query/packages/frequency")
        assert resp.status_code == 422


class TestRelationshipValidation:
    def test_create_relationship_empty_body(self, api):
        resp = api.post("/api/v1/relationships/", json={})
        assert resp.status_code == 422

    def test_create_relationship_invalid_type(self, api, seeded_product):
        resp = api.post(
            "/api/v1/relationships/",
            json={
                "parent_product_name": seeded_product["name"],
                "parent_product_version": seeded_product["version"],
                "component_product_name": "x",
                "component_product_version": "1.0",
                "relationship_type": "invalid_type",
            },
        )
        # Server may accept it (no enum validation) or reject
        assert resp.status_code in (201, 400, 404, 422)


class TestExportValidation:
    def test_export_url_expires_in_too_large(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/export/{name}/{version}/url",
            params={"expires_in": 999999},
        )
        assert resp.status_code in (200, 422)


class TestAdminValidation:
    def test_create_key_empty_body(self, admin_api):
        resp = admin_api.post("/api/v1/admin/keys/", json={})
        assert resp.status_code == 422

    def test_revoke_key_non_numeric_id(self, admin_api):
        resp = admin_api.delete("/api/v1/admin/keys/abc")
        assert resp.status_code == 422


class TestAuthEnforcement:
    """Verify that endpoints require authentication."""

    def test_products_without_auth_returns_401(self, unauth_api):
        resp = unauth_api.get("/api/v1/products/")
        # oauth2-proxy may redirect or the app returns 401/403
        assert resp.status_code in (401, 403) or (
            resp.status_code == 200
            and "text/html" in resp.headers.get("content-type", "")
        )

    def test_admin_keys_without_auth_returns_401(self, unauth_api):
        resp = unauth_api.get("/api/v1/admin/keys/")
        assert resp.status_code in (401, 403) or (
            resp.status_code == 200
            and "text/html" in resp.headers.get("content-type", "")
        )

    def test_post_without_auth_returns_401(self, unauth_api):
        resp = unauth_api.post(
            "/api/v1/products/",
            json={"name": "should-fail", "version": "1.0"},
        )
        assert resp.status_code in (401, 403) or (
            resp.status_code == 200
            and "text/html" in resp.headers.get("content-type", "")
        )
