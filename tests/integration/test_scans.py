"""Integration tests for scan endpoints (list, get, import, delete)."""

import gzip
import io
import json
import uuid

import pytest

pytestmark = pytest.mark.integration

MINIMAL_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "scan-test-sbom",
    "documentNamespace": "https://syfter.test/scan-integration",
    "creationInfo": {
        "created": "2025-01-01T00:00:00Z",
        "creators": ["Tool: integration-test"],
    },
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-curl",
            "name": "curl",
            "versionInfo": "8.6.0",
            "downloadLocation": "NOASSERTION",
        },
    ],
}

MINIMAL_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "zlib",
            "version": "1.3.1",
            "purl": "pkg:rpm/redhat/zlib@1.3.1",
        },
    ],
}


def _gz_json(obj: dict) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(json.dumps(obj).encode())
    return buf.getvalue()


class TestListScans:
    def test_list_scans_returns_array(self, api):
        resp = api.get("/api/v1/scans/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_scans_with_limit(self, api):
        resp = api.get("/api/v1/scans/", params={"limit": 3})
        assert resp.status_code == 200
        assert len(resp.json()) <= 3

    def test_list_scans_filter_by_product(self, api, seeded_product):
        resp = api.get(
            "/api/v1/scans/",
            params={"product_name": seeded_product["name"]},
        )
        assert resp.status_code == 200
        scans = resp.json()
        assert len(scans) >= 1
        assert all(s["product_name"] == seeded_product["name"] for s in scans)


class TestGetScan:
    def test_get_scan_by_id(self, api, seeded_product):
        scan_id = seeded_product["import"]["id"]
        resp = api.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == scan_id
        assert data["product_name"] == seeded_product["name"]
        assert "package_count" in data
        assert "scan_timestamp" in data
        assert "source_type" in data

    def test_get_nonexistent_scan_returns_404(self, api):
        resp = api.get("/api/v1/scans/999999999")
        assert resp.status_code == 404


class TestImportSBOM:
    def test_import_spdx(self, api, cleanup_products):
        name = f"inttest-import-spdx-{uuid.uuid4().hex[:8]}"
        resp = api.post(
            "/api/v1/scans/import",
            data={
                "product_name": name,
                "product_version": "1.0",
                "source_type": "sbom",
            },
            files={
                "sbom": ("test.spdx.json.gz", _gz_json(MINIMAL_SPDX), "application/octet-stream"),
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["product_name"] == name
        assert data["sbom_format"] == "spdx"
        assert data["package_count"] >= 1
        cleanup_products.append((name, "1.0"))

    def test_import_cyclonedx(self, api, cleanup_products):
        name = f"inttest-import-cdx-{uuid.uuid4().hex[:8]}"
        resp = api.post(
            "/api/v1/scans/import",
            data={
                "product_name": name,
                "product_version": "1.0",
                "source_type": "sbom",
            },
            files={
                "sbom": ("test.cdx.json.gz", _gz_json(MINIMAL_CYCLONEDX), "application/octet-stream"),
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["product_name"] == name
        assert data["sbom_format"] == "cyclonedx"
        assert data["package_count"] >= 1
        cleanup_products.append((name, "1.0"))

    def test_import_plain_json(self, api, cleanup_products):
        """Import accepts plain (non-gzipped) JSON as well."""
        name = f"inttest-import-plain-{uuid.uuid4().hex[:8]}"
        sbom_bytes = json.dumps(MINIMAL_SPDX).encode()
        resp = api.post(
            "/api/v1/scans/import",
            data={
                "product_name": name,
                "product_version": "1.0",
            },
            files={
                "sbom": ("test.spdx.json", sbom_bytes, "application/json"),
            },
        )
        assert resp.status_code == 201
        cleanup_products.append((name, "1.0"))

    def test_import_replaces_existing_scan(self, api, cleanup_products):
        name = f"inttest-import-replace-{uuid.uuid4().hex[:8]}"
        for _ in range(2):
            resp = api.post(
                "/api/v1/scans/import",
                data={
                    "product_name": name,
                    "product_version": "1.0",
                    "source_type": "sbom",
                },
                files={
                    "sbom": ("test.spdx.json.gz", _gz_json(MINIMAL_SPDX), "application/octet-stream"),
                },
            )
            assert resp.status_code == 201
        cleanup_products.append((name, "1.0"))

        scans = api.get(
            "/api/v1/scans/", params={"product_name": name}
        ).json()
        assert len(scans) == 1

    def test_import_missing_sbom_file_returns_422(self, api):
        resp = api.post(
            "/api/v1/scans/import",
            data={"product_name": "x", "product_version": "1.0"},
        )
        assert resp.status_code == 422

    def test_import_missing_product_name_returns_422(self, api):
        resp = api.post(
            "/api/v1/scans/import",
            data={"product_version": "1.0"},
            files={
                "sbom": ("test.json.gz", _gz_json(MINIMAL_SPDX), "application/octet-stream"),
            },
        )
        assert resp.status_code == 422


class TestDeleteScan:
    def test_delete_scan(self, api, cleanup_products):
        name = f"inttest-delscan-{uuid.uuid4().hex[:8]}"
        import_resp = api.post(
            "/api/v1/scans/import",
            data={
                "product_name": name,
                "product_version": "1.0",
                "source_type": "sbom",
            },
            files={
                "sbom": ("test.spdx.json.gz", _gz_json(MINIMAL_SPDX), "application/octet-stream"),
            },
        )
        assert import_resp.status_code == 201
        scan_id = import_resp.json()["id"]
        cleanup_products.append((name, "1.0"))

        resp = api.delete(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 204

        resp = api.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 404

    def test_delete_nonexistent_scan_returns_404(self, api):
        resp = api.delete("/api/v1/scans/999999999")
        assert resp.status_code == 404
