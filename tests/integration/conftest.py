"""
Integration test fixtures for Syfter API.

Run with:
    SYFTER_TEST_SERVER=https://syfter.stage.lightwell.redhat.com \
    SYFTER_API_KEY=<your-api-key> \
    pytest tests/integration/ -m integration

The staging server is behind oauth2-proxy. The X-API-Key header passes
through the proxy to the Syfter backend for authentication.
"""

import gzip
import io
import json
import os
import uuid
from pathlib import Path

import httpx
import pytest


INTEGRATION_BASE_URL = os.environ.get(
    "SYFTER_TEST_SERVER", "https://syfter.stage.lightwell.redhat.com"
)

TEST_PREFIX = "inttest"
TEST_TIMEOUT = 30.0


def _unique_name(base: str) -> str:
    return f"{TEST_PREFIX}-{base}-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def base_url() -> str:
    url = os.environ.get("SYFTER_TEST_SERVER")
    if not url:
        pytest.skip("SYFTER_TEST_SERVER not set")
    return url.rstrip("/")


@pytest.fixture(scope="session")
def api_key() -> str:
    key = os.environ.get("SYFTER_API_KEY")
    if not key:
        pytest.skip("SYFTER_API_KEY not set")
    return key


@pytest.fixture(scope="session")
def api(base_url, api_key) -> httpx.Client:
    """httpx client with auth headers pointing at the staging server."""
    client = httpx.Client(
        base_url=base_url,
        headers={"X-API-Key": api_key},
        timeout=TEST_TIMEOUT,
        follow_redirects=True,
    )
    yield client
    client.close()


@pytest.fixture(scope="session")
def admin_api(base_url) -> httpx.Client:
    """httpx client with admin API key for admin-only endpoints."""
    key = os.environ.get("SYFTER_ADMIN_API_KEY", os.environ.get("SYFTER_API_KEY"))
    if not key:
        pytest.skip("SYFTER_ADMIN_API_KEY or SYFTER_API_KEY not set")
    client = httpx.Client(
        base_url=base_url,
        headers={"X-API-Key": key},
        timeout=TEST_TIMEOUT,
        follow_redirects=True,
    )
    yield client
    client.close()


@pytest.fixture(scope="session")
def unauth_api(base_url) -> httpx.Client:
    """httpx client with NO auth headers."""
    client = httpx.Client(
        base_url=base_url,
        timeout=TEST_TIMEOUT,
        follow_redirects=True,
    )
    yield client
    client.close()


# ---------------------------------------------------------------------------
# Sample SBOM fixtures
# ---------------------------------------------------------------------------

SAMPLE_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "integration-test-sbom",
    "documentNamespace": "https://syfter.test/integration",
    "creationInfo": {
        "created": "2025-01-01T00:00:00Z",
        "creators": ["Tool: integration-test"],
    },
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-bash",
            "name": "bash",
            "versionInfo": "5.2.26",
            "downloadLocation": "NOASSERTION",
            "supplier": "Organization: Red Hat",
        },
        {
            "SPDXID": "SPDXRef-Package-openssl",
            "name": "openssl-libs",
            "versionInfo": "3.2.2",
            "downloadLocation": "NOASSERTION",
            "supplier": "Organization: Red Hat",
        },
        {
            "SPDXID": "SPDXRef-Package-glibc",
            "name": "glibc",
            "versionInfo": "2.39",
            "downloadLocation": "NOASSERTION",
            "supplier": "Organization: Red Hat",
        },
    ],
}


def _make_spdx_gz(sbom_dict: dict) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(json.dumps(sbom_dict).encode())
    return buf.getvalue()


@pytest.fixture(scope="session")
def seeded_product(api):
    """Seed a product via SBOM import and return its (name, version).

    Cleans up the product after the test session.
    """
    product_name = _unique_name("spdx")
    product_version = "1.0.0"

    sbom_bytes = _make_spdx_gz(SAMPLE_SPDX)

    resp = api.post(
        "/api/v1/scans/import",
        data={
            "product_name": product_name,
            "product_version": product_version,
            "source_type": "sbom",
        },
        files={"sbom": ("test.spdx.json.gz", sbom_bytes, "application/octet-stream")},
    )

    if resp.status_code == 201:
        yield {"name": product_name, "version": product_version, "import": resp.json()}
    else:
        pytest.skip(
            f"Failed to seed product via import: {resp.status_code} {resp.text}"
        )
        return

    api.delete(f"/api/v1/products/{product_name}/{product_version}")


@pytest.fixture
def unique_product_name():
    return _unique_name("prod")


@pytest.fixture
def unique_hostname():
    return _unique_name("host") + ".example.com"


@pytest.fixture
def cleanup_products(api):
    """Track products created during a test and delete them afterwards."""
    created = []
    yield created
    for name, version in created:
        api.delete(f"/api/v1/products/{name}/{version}")


@pytest.fixture
def cleanup_systems(api):
    """Track systems created during a test and delete them afterwards."""
    created = []
    yield created
    for hostname in created:
        api.delete(f"/api/v1/systems/{hostname}")


@pytest.fixture
def cleanup_relationships(api):
    """Track relationships created during a test and delete them afterwards."""
    created = []
    yield created
    for rel_id in created:
        api.delete(f"/api/v1/relationships/{rel_id}")
