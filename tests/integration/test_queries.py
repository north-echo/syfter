"""Integration tests for query endpoints (packages, files, stats, deps, etc)."""

import pytest

pytestmark = pytest.mark.integration


class TestSearchPackages:
    def test_search_packages_no_filter(self, api):
        resp = api.get("/api/v1/query/packages", params={"limit": 5})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_search_packages_by_name(self, api, seeded_product):
        resp = api.get("/api/v1/query/packages", params={"name": "bash"})
        assert resp.status_code == 200
        pkgs = resp.json()
        assert isinstance(pkgs, list)

    def test_search_packages_by_name_wildcard(self, api):
        resp = api.get("/api/v1/query/packages", params={"name": "open%"})
        assert resp.status_code == 200

    def test_search_packages_by_product(self, api, seeded_product):
        resp = api.get(
            "/api/v1/query/packages",
            params={
                "product_name": seeded_product["name"],
                "product_version": seeded_product["version"],
                "limit": 10,
            },
        )
        assert resp.status_code == 200
        pkgs = resp.json()
        assert len(pkgs) >= 1
        for pkg in pkgs:
            assert pkg["product_name"] == seeded_product["name"]

    def test_search_packages_response_schema(self, api, seeded_product):
        resp = api.get(
            "/api/v1/query/packages",
            params={"product_name": seeded_product["name"], "limit": 1},
        )
        assert resp.status_code == 200
        pkgs = resp.json()
        if pkgs:
            pkg = pkgs[0]
            for field in ("id", "name", "version", "product_name", "product_version"):
                assert field in pkg, f"Missing field: {field}"

    def test_search_packages_by_version(self, api):
        resp = api.get(
            "/api/v1/query/packages",
            params={"name": "bash", "pkg_version": "%"},
        )
        assert resp.status_code == 200

    def test_search_packages_layer_type_filter(self, api):
        resp = api.get(
            "/api/v1/query/packages",
            params={"name": "%", "layer_type": "base", "limit": 5},
        )
        assert resp.status_code == 200


class TestPackageFrequency:
    def test_package_frequency(self, api, seeded_product):
        resp = api.get(
            "/api/v1/query/packages/frequency",
            params={"name": "bash"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_package_frequency_with_product_filter(self, api, seeded_product):
        resp = api.get(
            "/api/v1/query/packages/frequency",
            params={
                "name": "%",
                "product_name": seeded_product["name"],
                "limit": 5,
            },
        )
        assert resp.status_code == 200

    def test_package_frequency_requires_name(self, api):
        resp = api.get("/api/v1/query/packages/frequency")
        assert resp.status_code == 422

    def test_package_frequency_response_schema(self, api):
        resp = api.get(
            "/api/v1/query/packages/frequency",
            params={"name": "%", "limit": 1},
        )
        assert resp.status_code == 200
        data = resp.json()
        if data:
            entry = data[0]
            assert "version" in entry
            assert "sbom_count" in entry
            assert "products" in entry
            assert isinstance(entry["products"], list)


class TestSearchFiles:
    def test_search_files_no_filter(self, api):
        resp = api.get("/api/v1/query/files", params={"limit": 5})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_search_files_by_path(self, api):
        resp = api.get(
            "/api/v1/query/files", params={"path": "%/bin/%", "limit": 5}
        )
        assert resp.status_code == 200

    def test_search_files_by_digest(self, api):
        resp = api.get(
            "/api/v1/query/files",
            params={"digest": "0000000000000000000000000000000000000000"},
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_search_files_by_product(self, api, seeded_product):
        resp = api.get(
            "/api/v1/query/files",
            params={
                "product_name": seeded_product["name"],
                "limit": 5,
            },
        )
        assert resp.status_code == 200

    def test_search_files_response_schema(self, api):
        resp = api.get("/api/v1/query/files", params={"limit": 1})
        assert resp.status_code == 200
        files = resp.json()
        if files:
            f = files[0]
            for field in ("id", "path", "package_name", "product_name"):
                assert field in f, f"Missing field: {field}"


class TestGetStats:
    def test_get_stats(self, api):
        resp = api.get("/api/v1/query/stats")
        assert resp.status_code == 200
        data = resp.json()
        for field in ("products", "scans", "packages", "files", "storage_type", "database_type"):
            assert field in data, f"Missing stats field: {field}"
        assert isinstance(data["products"], int)
        assert isinstance(data["packages"], int)

    def test_stats_counts_are_non_negative(self, api):
        data = api.get("/api/v1/query/stats").json()
        for field in ("products", "scans", "packages", "files"):
            assert data[field] >= 0


class TestListAllPackages:
    def test_list_all_packages(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/query/list/packages/{name}/{version}")
        assert resp.status_code == 200
        pkgs = resp.json()
        assert isinstance(pkgs, list)
        assert len(pkgs) >= 1

    def test_list_all_packages_nonexistent_product(self, api):
        resp = api.get("/api/v1/query/list/packages/nonexistent/0.0")
        assert resp.status_code in (200, 404)


class TestListAllFiles:
    def test_list_all_files(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/query/list/files/{name}/{version}")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_all_files_nonexistent_product(self, api):
        resp = api.get("/api/v1/query/list/files/nonexistent/0.0")
        assert resp.status_code in (200, 404)


class TestSearchDependencies:
    def test_search_dependencies_no_filter(self, api):
        resp = api.get("/api/v1/query/dependencies", params={"limit": 5})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_search_dependencies_by_package(self, api):
        resp = api.get(
            "/api/v1/query/dependencies",
            params={"package_name": "bash", "limit": 5},
        )
        assert resp.status_code == 200

    def test_search_dependencies_by_type(self, api):
        resp = api.get(
            "/api/v1/query/dependencies",
            params={"dependency_type": "requires", "limit": 5},
        )
        assert resp.status_code == 200

    def test_search_dependencies_response_schema(self, api):
        resp = api.get("/api/v1/query/dependencies", params={"limit": 1})
        assert resp.status_code == 200
        deps = resp.json()
        if deps:
            dep = deps[0]
            for field in ("id", "dependency_name", "dependency_type", "product_name"):
                assert field in dep, f"Missing field: {field}"


class TestSearchComponents:
    def test_search_components_no_filter(self, api):
        resp = api.get("/api/v1/query/components", params={"limit": 5})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_search_components_by_product(self, api, seeded_product):
        resp = api.get(
            "/api/v1/query/components",
            params={"product_name": seeded_product["name"]},
        )
        assert resp.status_code == 200

    def test_search_components_response_schema(self, api):
        resp = api.get("/api/v1/query/components", params={"limit": 1})
        assert resp.status_code == 200
        comps = resp.json()
        if comps:
            c = comps[0]
            for field in (
                "id", "parent_product_name", "component_product_name",
                "relationship_type",
            ):
                assert field in c


class TestGetProvenance:
    def test_provenance_for_seeded_product(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(f"/api/v1/query/provenance/{name}/{version}")
        assert resp.status_code == 200

    def test_provenance_nonexistent_product(self, api):
        resp = api.get("/api/v1/query/provenance/nonexistent/0.0")
        assert resp.status_code in (200, 404)

    def test_provenance_with_package_filter(self, api, seeded_product):
        name = seeded_product["name"]
        version = seeded_product["version"]
        resp = api.get(
            f"/api/v1/query/provenance/{name}/{version}",
            params={"package_name_filter": "bash"},
        )
        assert resp.status_code == 200


class TestTracePackage:
    def test_trace_package(self, api):
        resp = api.get("/api/v1/query/trace", params={"name": "bash"})
        assert resp.status_code == 200

    def test_trace_package_requires_name(self, api):
        resp = api.get("/api/v1/query/trace")
        assert resp.status_code == 422

    def test_trace_package_with_version(self, api):
        resp = api.get(
            "/api/v1/query/trace",
            params={"name": "bash", "pkg_version": "%"},
        )
        assert resp.status_code == 200


class TestSystemPackages:
    def test_search_system_packages(self, api):
        resp = api.get(
            "/api/v1/query/systems/packages", params={"limit": 5}
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_search_system_packages_by_hostname(self, api):
        resp = api.get(
            "/api/v1/query/systems/packages",
            params={"hostname": "nonexistent.example.com"},
        )
        assert resp.status_code == 200
        assert resp.json() == []


class TestSystemFiles:
    def test_search_system_files(self, api):
        resp = api.get(
            "/api/v1/query/systems/files", params={"limit": 5}
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestListSystemPackages:
    def test_list_system_packages_nonexistent(self, api):
        resp = api.get(
            "/api/v1/query/systems/list/packages/nonexistent.example.com"
        )
        assert resp.status_code in (200, 404)


class TestListSystemFiles:
    def test_list_system_files_nonexistent(self, api):
        resp = api.get(
            "/api/v1/query/systems/list/files/nonexistent.example.com"
        )
        assert resp.status_code in (200, 404)
