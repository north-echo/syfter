"""Integration tests for product CRUD endpoints."""

import pytest

pytestmark = pytest.mark.integration


class TestListProducts:
    def test_list_products_returns_array(self, api):
        resp = api.get("/api/v1/products/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_products_with_limit(self, api):
        resp = api.get("/api/v1/products/", params={"limit": 5})
        assert resp.status_code == 200
        assert len(resp.json()) <= 5

    def test_list_products_with_offset(self, api):
        resp = api.get("/api/v1/products/", params={"limit": 1, "offset": 0})
        assert resp.status_code == 200

    def test_list_products_name_filter(self, api, seeded_product):
        resp = api.get(
            "/api/v1/products/", params={"name": seeded_product["name"]}
        )
        assert resp.status_code == 200
        products = resp.json()
        assert len(products) >= 1
        assert any(p["name"] == seeded_product["name"] for p in products)

    def test_list_products_name_wildcard(self, api):
        resp = api.get("/api/v1/products/", params={"name": "inttest%"})
        assert resp.status_code == 200

    def test_list_products_has_x_total_count(self, api):
        resp = api.get("/api/v1/products/")
        assert resp.status_code == 200
        assert "x-total-count" in resp.headers


class TestCreateProduct:
    def test_create_product(self, api, unique_product_name, cleanup_products):
        resp = api.post(
            "/api/v1/products/",
            json={
                "name": unique_product_name,
                "version": "1.0",
                "description": "Integration test product",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == unique_product_name
        assert data["version"] == "1.0"
        assert data["vendor"] == "Red Hat"
        assert data["description"] == "Integration test product"
        assert "id" in data
        assert "created_at" in data
        cleanup_products.append((unique_product_name, "1.0"))

    def test_create_product_with_all_fields(self, api, cleanup_products):
        name = f"inttest-full-{__import__('uuid').uuid4().hex[:8]}"
        resp = api.post(
            "/api/v1/products/",
            json={
                "name": name,
                "version": "2.0",
                "vendor": "Test Vendor",
                "cpe_vendor": "test_vendor",
                "cpe_product": "test_product",
                "purl_namespace": "test",
                "description": "Full fields test",
                "ps_update_stream": "test-2.0.z",
                "ps_module": "test-2",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor"] == "Test Vendor"
        assert data["cpe_vendor"] == "test_vendor"
        assert data["cpe_product"] == "test_product"
        assert data["purl_namespace"] == "test"
        assert data["ps_update_stream"] == "test-2.0.z"
        assert data["ps_module"] == "test-2"
        cleanup_products.append((name, "2.0"))

    def test_create_duplicate_product_returns_409(self, api, seeded_product):
        resp = api.post(
            "/api/v1/products/",
            json={
                "name": seeded_product["name"],
                "version": seeded_product["version"],
            },
        )
        assert resp.status_code == 409

    def test_create_product_missing_name_returns_422(self, api):
        resp = api.post("/api/v1/products/", json={"version": "1.0"})
        assert resp.status_code == 422

    def test_create_product_missing_version_returns_422(self, api):
        resp = api.post("/api/v1/products/", json={"name": "test"})
        assert resp.status_code == 422


class TestGetProduct:
    def test_get_existing_product(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/products/{name}/{version}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == name
        assert data["version"] == version
        assert "scan_count" in data
        assert "total_packages" in data
        assert "total_files" in data

    def test_get_nonexistent_product_returns_404(self, api):
        resp = api.get("/api/v1/products/nonexistent-product/0.0.0")
        assert resp.status_code == 404


class TestDeleteProduct:
    def test_delete_product(self, api, unique_product_name):
        api.post(
            "/api/v1/products/",
            json={"name": unique_product_name, "version": "99.0"},
        )
        resp = api.delete(f"/api/v1/products/{unique_product_name}/99.0")
        assert resp.status_code == 204

        resp = api.get(f"/api/v1/products/{unique_product_name}/99.0")
        assert resp.status_code == 404

    def test_delete_nonexistent_product_returns_404(self, api):
        resp = api.delete("/api/v1/products/nonexistent-product/0.0.0")
        assert resp.status_code == 404


class TestProductLayers:
    def test_get_product_layers(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/products/{name}/{version}/layers")
        assert resp.status_code in (200, 404)

    def test_get_product_attestations(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/products/{name}/{version}/attestations")
        assert resp.status_code in (200, 404)
