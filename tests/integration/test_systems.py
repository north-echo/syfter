"""Integration tests for system CRUD endpoints."""

import pytest

pytestmark = pytest.mark.integration


class TestListSystems:
    def test_list_systems_returns_array(self, api):
        resp = api.get("/api/v1/systems/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_systems_with_limit(self, api):
        resp = api.get("/api/v1/systems/", params={"limit": 5})
        assert resp.status_code == 200
        assert len(resp.json()) <= 5

    def test_list_systems_with_tag_filter(self, api):
        resp = api.get("/api/v1/systems/", params={"tag": "nonexistent-tag"})
        assert resp.status_code == 200
        assert resp.json() == []


class TestListTags:
    def test_list_tags_returns_array(self, api):
        resp = api.get("/api/v1/systems/tags/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestCreateSystem:
    def test_create_system_minimal(self, api, unique_hostname, cleanup_systems):
        resp = api.post(
            "/api/v1/systems/",
            json={"hostname": unique_hostname},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["hostname"] == unique_hostname
        assert "id" in data
        assert "created_at" in data
        cleanup_systems.append(unique_hostname)

    def test_create_system_full_fields(self, api, cleanup_systems):
        hostname = f"inttest-full-{__import__('uuid').uuid4().hex[:8]}.example.com"
        resp = api.post(
            "/api/v1/systems/",
            json={
                "hostname": hostname,
                "ip_address": "10.0.0.42",
                "tag": "integration-test",
                "os_name": "Red Hat Enterprise Linux",
                "os_version": "9.4",
                "arch": "x86_64",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["hostname"] == hostname
        assert data["ip_address"] == "10.0.0.42"
        assert data["tag"] == "integration-test"
        assert data["os_name"] == "Red Hat Enterprise Linux"
        assert data["os_version"] == "9.4"
        assert data["arch"] == "x86_64"
        cleanup_systems.append(hostname)

    def test_create_system_missing_hostname_returns_422(self, api):
        resp = api.post("/api/v1/systems/", json={})
        assert resp.status_code == 422


class TestGetSystem:
    def test_get_existing_system(self, api, unique_hostname, cleanup_systems):
        api.post("/api/v1/systems/", json={"hostname": unique_hostname})
        cleanup_systems.append(unique_hostname)

        resp = api.get(f"/api/v1/systems/{unique_hostname}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["hostname"] == unique_hostname
        assert "scan_count" in data
        assert "total_packages" in data

    def test_get_nonexistent_system_returns_404(self, api):
        resp = api.get("/api/v1/systems/nonexistent-host.example.com")
        assert resp.status_code == 404


class TestUpdateSystem:
    def test_update_system_metadata(self, api, unique_hostname, cleanup_systems):
        api.post("/api/v1/systems/", json={"hostname": unique_hostname})
        cleanup_systems.append(unique_hostname)

        resp = api.put(
            f"/api/v1/systems/{unique_hostname}",
            json={
                "hostname": unique_hostname,
                "tag": "updated-tag",
                "os_version": "10.0",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tag"] == "updated-tag"
        assert data["os_version"] == "10.0"

    def test_update_nonexistent_system_returns_404(self, api):
        resp = api.put(
            "/api/v1/systems/nonexistent.example.com",
            json={"hostname": "nonexistent.example.com"},
        )
        assert resp.status_code == 404


class TestDeleteSystem:
    def test_delete_system(self, api, unique_hostname):
        api.post("/api/v1/systems/", json={"hostname": unique_hostname})

        resp = api.delete(f"/api/v1/systems/{unique_hostname}")
        assert resp.status_code == 204

        resp = api.get(f"/api/v1/systems/{unique_hostname}")
        assert resp.status_code == 404

    def test_delete_nonexistent_system_returns_404(self, api):
        resp = api.delete("/api/v1/systems/nonexistent.example.com")
        assert resp.status_code == 404


class TestSystemTagFilter:
    def test_list_systems_filtered_by_tag(self, api, cleanup_systems):
        tag = f"inttest-tag-{__import__('uuid').uuid4().hex[:8]}"
        hostname = f"inttest-tagged-{__import__('uuid').uuid4().hex[:8]}.example.com"

        api.post(
            "/api/v1/systems/",
            json={"hostname": hostname, "tag": tag},
        )
        cleanup_systems.append(hostname)

        resp = api.get("/api/v1/systems/", params={"tag": tag})
        assert resp.status_code == 200
        systems = resp.json()
        assert len(systems) >= 1
        assert all(s["tag"] == tag for s in systems)

    def test_list_tags_includes_created_tag(self, api, cleanup_systems):
        tag = f"inttest-taglist-{__import__('uuid').uuid4().hex[:8]}"
        hostname = f"inttest-taglist-{__import__('uuid').uuid4().hex[:8]}.example.com"

        api.post(
            "/api/v1/systems/",
            json={"hostname": hostname, "tag": tag},
        )
        cleanup_systems.append(hostname)

        resp = api.get("/api/v1/systems/tags/")
        assert resp.status_code == 200
        assert tag in resp.json()
