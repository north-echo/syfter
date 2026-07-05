"""Integration tests for container layer endpoints."""

import pytest

pytestmark = pytest.mark.integration


class TestGetLayers:
    def test_get_layers_for_seeded_product(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/layers/{name}/{version}")
        # SPDX-imported products may not have layer data
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.json()
            assert "product_name" in data
            assert "layers" in data
            assert isinstance(data["layers"], list)
            for field in (
                "total_layers", "base_layers", "app_layers",
                "source_path", "source_type",
            ):
                assert field in data

    def test_get_layers_nonexistent_product(self, api):
        resp = api.get("/api/v1/layers/nonexistent/0.0")
        assert resp.status_code == 404

    def test_layer_response_schema(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/layers/{name}/{version}")
        if resp.status_code != 200:
            pytest.skip("No layer data for seeded product")
        layers = resp.json()["layers"]
        if layers:
            layer = layers[0]
            for field in ("layer_id", "layer_index", "source_image", "is_base", "command"):
                assert field in layer, f"Missing field: {field}"


class TestGetLayerPackages:
    def test_get_layer_packages(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/layers/{name}/{version}/packages",
            params={"limit": 10},
        )
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            pkgs = resp.json()
            assert isinstance(pkgs, list)

    def test_get_layer_packages_base_filter(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/layers/{name}/{version}/packages",
            params={"layer_type": "base", "limit": 5},
        )
        assert resp.status_code in (200, 404)

    def test_get_layer_packages_app_filter(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/layers/{name}/{version}/packages",
            params={"layer_type": "app", "limit": 5},
        )
        assert resp.status_code in (200, 404)

    def test_layer_package_response_schema(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/layers/{name}/{version}/packages",
            params={"limit": 1},
        )
        if resp.status_code != 200 or not resp.json():
            pytest.skip("No layer packages for seeded product")
        pkg = resp.json()[0]
        for field in ("id", "name", "version", "layer_id", "layer_index", "source_image"):
            assert field in pkg, f"Missing field: {field}"


class TestGetBaseImage:
    def test_get_base_image(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/layers/{name}/{version}/base-image")
        assert resp.status_code in (200, 404)

    def test_get_base_image_nonexistent(self, api):
        resp = api.get("/api/v1/layers/nonexistent/0.0/base-image")
        assert resp.status_code == 404


class TestSearchPackagesByLayer:
    def test_search_by_layer_no_filter(self, api):
        resp = api.get(
            "/api/v1/layers/search/packages", params={"limit": 5}
        )
        assert resp.status_code == 200

    def test_search_by_layer_name_filter(self, api):
        resp = api.get(
            "/api/v1/layers/search/packages",
            params={"name": "openssl%", "layer_type": "base", "limit": 5},
        )
        assert resp.status_code == 200

    def test_search_by_layer_product_filter(self, api, seeded_product):
        resp = api.get(
            "/api/v1/layers/search/packages",
            params={
                "product_name": seeded_product["name"],
                "limit": 5,
            },
        )
        assert resp.status_code == 200


class TestGetLayerChains:
    def test_get_layer_chains(self, api):
        resp = api.get("/api/v1/layers/chains")
        assert resp.status_code == 200


class TestEnrichLayers:
    def test_enrich_layers(self, api):
        resp = api.post("/api/v1/layers/enrich")
        assert resp.status_code == 200
