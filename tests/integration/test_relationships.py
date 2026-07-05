"""Integration tests for component relationship endpoints."""

import uuid

import pytest

pytestmark = pytest.mark.integration


class TestListRelationships:
    def test_list_relationships_returns_array(self, api):
        resp = api.get("/api/v1/relationships/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_relationships_with_limit(self, api):
        resp = api.get("/api/v1/relationships/", params={"limit": 5})
        assert resp.status_code == 200
        assert len(resp.json()) <= 5


class TestCreateRelationship:
    def test_create_layered_relationship(
        self, api, seeded_product, cleanup_products, cleanup_relationships,
    ):
        comp_name = f"inttest-comp-{uuid.uuid4().hex[:8]}"
        api.post(
            "/api/v1/products/",
            json={"name": comp_name, "version": "1.0"},
        )
        cleanup_products.append((comp_name, "1.0"))

        resp = api.post(
            "/api/v1/relationships/",
            json={
                "parent_product_name": seeded_product["name"],
                "parent_product_version": seeded_product["version"],
                "component_product_name": comp_name,
                "component_product_version": "1.0",
                "relationship_type": "layered",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["parent_product_name"] == seeded_product["name"]
        assert data["component_product_name"] == comp_name
        assert data["relationship_type"] == "layered"
        assert "id" in data
        assert "created_at" in data
        cleanup_relationships.append(data["id"])

    def test_create_maintained_relationship(
        self, api, seeded_product, cleanup_products, cleanup_relationships,
    ):
        comp_name = f"inttest-maint-{uuid.uuid4().hex[:8]}"
        api.post(
            "/api/v1/products/",
            json={"name": comp_name, "version": "1.0"},
        )
        cleanup_products.append((comp_name, "1.0"))

        resp = api.post(
            "/api/v1/relationships/",
            json={
                "parent_product_name": seeded_product["name"],
                "parent_product_version": seeded_product["version"],
                "component_product_name": comp_name,
                "component_product_version": "1.0",
                "relationship_type": "maintained",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["relationship_type"] == "maintained"
        cleanup_relationships.append(resp.json()["id"])

    def test_create_duplicate_relationship_returns_409(
        self, api, seeded_product, cleanup_products, cleanup_relationships,
    ):
        comp_name = f"inttest-dup-{uuid.uuid4().hex[:8]}"
        api.post(
            "/api/v1/products/",
            json={"name": comp_name, "version": "1.0"},
        )
        cleanup_products.append((comp_name, "1.0"))

        payload = {
            "parent_product_name": seeded_product["name"],
            "parent_product_version": seeded_product["version"],
            "component_product_name": comp_name,
            "component_product_version": "1.0",
        }
        first = api.post("/api/v1/relationships/", json=payload)
        assert first.status_code == 201
        cleanup_relationships.append(first.json()["id"])

        second = api.post("/api/v1/relationships/", json=payload)
        assert second.status_code == 409

    def test_create_relationship_missing_product_returns_404(self, api, seeded_product):
        resp = api.post(
            "/api/v1/relationships/",
            json={
                "parent_product_name": seeded_product["name"],
                "parent_product_version": seeded_product["version"],
                "component_product_name": "nonexistent-product",
                "component_product_version": "0.0.0",
            },
        )
        assert resp.status_code == 404

    def test_create_relationship_missing_fields_returns_422(self, api):
        resp = api.post(
            "/api/v1/relationships/",
            json={"parent_product_name": "x"},
        )
        assert resp.status_code == 422


class TestDeleteRelationship:
    def test_delete_relationship(
        self, api, seeded_product, cleanup_products,
    ):
        comp_name = f"inttest-delrel-{uuid.uuid4().hex[:8]}"
        api.post(
            "/api/v1/products/",
            json={"name": comp_name, "version": "1.0"},
        )
        cleanup_products.append((comp_name, "1.0"))

        create_resp = api.post(
            "/api/v1/relationships/",
            json={
                "parent_product_name": seeded_product["name"],
                "parent_product_version": seeded_product["version"],
                "component_product_name": comp_name,
                "component_product_version": "1.0",
            },
        )
        assert create_resp.status_code == 201
        rel_id = create_resp.json()["id"]

        resp = api.delete(f"/api/v1/relationships/{rel_id}")
        assert resp.status_code == 204

    def test_delete_nonexistent_relationship_returns_404(self, api):
        resp = api.delete("/api/v1/relationships/999999999")
        assert resp.status_code == 404
