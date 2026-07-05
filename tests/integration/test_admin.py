"""Integration tests for admin endpoints (API key management, access log)."""

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.auth]


class TestListApiKeys:
    def test_list_api_keys(self, admin_api):
        resp = admin_api.get("/api/v1/admin/keys/")
        assert resp.status_code == 200
        keys = resp.json()
        assert isinstance(keys, list)
        if keys:
            key = keys[0]
            for field in (
                "id", "key_prefix", "team_name", "is_active",
                "is_admin", "created_at",
            ):
                assert field in key, f"Missing field: {field}"
            assert "api_key" not in key


class TestCreateApiKey:
    def test_create_api_key(self, admin_api):
        resp = admin_api.post(
            "/api/v1/admin/keys/",
            json={
                "team_name": "inttest-team",
                "description": "Integration test key",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["team_name"] == "inttest-team"
        assert data["is_active"] is True
        assert data["is_admin"] is False
        assert "api_key" in data
        assert len(data["api_key"]) > 0
        assert "key_prefix" in data

        admin_api.delete(f"/api/v1/admin/keys/{data['id']}")

    def test_create_api_key_with_expiry(self, admin_api):
        resp = admin_api.post(
            "/api/v1/admin/keys/",
            json={
                "team_name": "inttest-expiry",
                "expires_in_days": 7,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["expires_at"] is not None

        admin_api.delete(f"/api/v1/admin/keys/{data['id']}")

    def test_create_api_key_missing_team_returns_422(self, admin_api):
        resp = admin_api.post(
            "/api/v1/admin/keys/",
            json={"description": "no team"},
        )
        assert resp.status_code == 422


class TestRevokeApiKey:
    def test_revoke_api_key(self, admin_api):
        create_resp = admin_api.post(
            "/api/v1/admin/keys/",
            json={"team_name": "inttest-revoke"},
        )
        assert create_resp.status_code == 201
        key_id = create_resp.json()["id"]

        resp = admin_api.delete(f"/api/v1/admin/keys/{key_id}")
        assert resp.status_code == 204

    def test_revoke_nonexistent_key_returns_404(self, admin_api):
        resp = admin_api.delete("/api/v1/admin/keys/999999999")
        assert resp.status_code == 404

    def test_revoked_key_cannot_authenticate(self, admin_api, base_url):
        import httpx

        create_resp = admin_api.post(
            "/api/v1/admin/keys/",
            json={"team_name": "inttest-revoke-auth"},
        )
        assert create_resp.status_code == 201
        data = create_resp.json()
        new_key = data["api_key"]
        key_id = data["id"]

        admin_api.delete(f"/api/v1/admin/keys/{key_id}")

        with httpx.Client(
            base_url=base_url,
            headers={"X-API-Key": new_key},
            timeout=30.0,
            follow_redirects=True,
        ) as client:
            resp = client.get("/api/v1/products/")
            assert resp.status_code in (401, 403)


class TestAccessLog:
    def test_get_access_log(self, admin_api):
        resp = admin_api.get("/api/v1/admin/access-log/")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_get_access_log_with_limit(self, admin_api):
        resp = admin_api.get(
            "/api/v1/admin/access-log/", params={"limit": 5}
        )
        assert resp.status_code == 200
        assert len(resp.json()) <= 5

    def test_get_access_log_with_team_filter(self, admin_api):
        resp = admin_api.get(
            "/api/v1/admin/access-log/",
            params={"team": "nonexistent-team"},
        )
        assert resp.status_code == 200

    def test_get_access_log_summary(self, admin_api):
        resp = admin_api.get("/api/v1/admin/access-log/summary")
        assert resp.status_code == 200
