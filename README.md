# Syfter

A fork of [syfter](https://github.com/vdanen/syfter) hardened for multi-team, large-scale SBOM management. Adds authentication, rate limiting, response caching, RPM dependency tracking, cross-product tracing, container attestation indexing, and query performance fixes for 20M+ package deployments.

## What This Fork Adds

| Capability | Upstream | This Fork |
|------------|----------|-----------|
| **Authentication** | None | API key auth (SHA-256, DB-backed) with per-team keys and admin management |
| **Rate limiting** | None | Per-key token bucket (60/min queries, 10/min uploads) |
| **Response caching** | None | In-process cache with auto-invalidation on mutations |
| **RPM dependency tracking** | None | 504M requires/provides relationships, queryable by package or dependency name |
| **Cross-product tracing** | None | `syfter trace` follows a package from RHEL repos through UBI base images into layered containers |
| **Attestation indexing** | None | Cosign SLSA provenance and SPDX document attestation metadata |
| **Component relationships** | None | Product-to-product composition mappings |
| **Products list** | N+1 COUNT queries | LATERAL join -- **16s to 0.4s** |
| **Package search** | Full table scan + sort | Subquery-first with COLLATE "C" index -- **30s timeout to 0.2s** |
| **Dependency search** | N/A | Composite index + PK sort -- **< 1s** across 504M rows |
| **Stats endpoint** | 5x COUNT(*) on large tables | Materialized view -- **16s to 97ms** |
| **Job queue** | Async with FK violations | Removed -- direct upload only |

All upstream features (scanning, SBOM enrichment, export, container layer tracking) are preserved.

## Current Scale

Tested in production with:
- 20.8 million packages
- 504 million RPM dependency relationships
- 7,557 products (RPM repos + container images + middleware)
- 1,038 cosign attestation records
- All query endpoints < 2 seconds

## Quick Start

```bash
# Start the server
SYFTER_AUTH_ENABLED=true \
SYFTER_ADMIN_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
SYFTER_DB_TYPE=postgresql \
SYFTER_PG_HOST=localhost \
SYFTER_PG_PASSWORD=changeme \
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000

# Health check (no auth required)
curl http://localhost:8000/health

# Create a team key
curl -X POST http://localhost:8000/api/v1/admin/keys/ \
  -H "X-API-Key: $SYFTER_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"team_name": "security"}'

# Use the team key
export SYFTER_API_KEY=<returned-key>
export SYFTER_SERVER=http://localhost:8000
syfter products
syfter query -n "openssl%"
```

## CLI

The CLI extends upstream with `trace` and `deps` commands:

```bash
export SYFTER_SERVER=https://your-server.example.com
export SYFTER_API_KEY=your-team-key

# Standard commands (same as upstream)
syfter scan /path/to/rpms -p rhel -v 10.1
syfter query -n "openssl%"
syfter products
syfter export -p rhel -v 10.0 -f spdx-json -o rhel.spdx.json

# Trace a package across the product stack
syfter trace openssl-libs

# Query RPM dependencies
syfter deps openssl-libs                          # what requires openssl-libs?
syfter deps --package curl --type requires        # what does curl require?
syfter deps openssl-libs -p rhel -v 9.6           # scoped to a product

# Component relationships
syfter relationships
```

## API Endpoints

All endpoints require API key authentication via `X-API-Key` header except `/health`.

### Query
- `GET /health` -- Health check (no auth)
- `GET /api/v1/query/stats` -- Database statistics (cached)
- `GET /api/v1/query/packages?name=<pattern>` -- Package search (LIKE patterns)
- `GET /api/v1/query/dependencies?package_name=&dependency_type=` -- RPM dependency search
- `GET /api/v1/query/provenance/{product}/{version}?package_name=` -- Cross-product provenance
- `GET /api/v1/products` -- Product listing (paginated, cached)

### Container Layers
- `GET /api/v1/layers/{product}/{version}` -- Layer chain for a container
- `GET /api/v1/layers/{product}/{version}/packages?layer_type=base` -- Packages by layer
- `GET /api/v1/layers/{product}/{version}/base-image` -- Base image identification
- `POST /api/v1/layers/enrich` -- Batch layer enrichment

### Attestations
- `GET /api/v1/products/{product}/{version}/attestations` -- Cosign attestation metadata

### Relationships
- `GET /api/v1/relationships/` -- List component relationships
- `POST /api/v1/relationships/` -- Create relationship
- `DELETE /api/v1/relationships/{id}` -- Delete relationship

### Admin
- `POST /api/v1/admin/keys/` -- Create API key
- `GET /api/v1/admin/keys/` -- List API keys
- `DELETE /api/v1/admin/keys/{id}` -- Revoke API key

### Upload
- `POST /api/v1/scans/upload` -- Upload scan results (multipart, supports `dependencies_json`, `image_layers_json`, `attestation_json`)

## Configuration

All settings via environment variables (same as upstream, plus these):

| Variable | Default | Description |
|----------|---------|-------------|
| `SYFTER_AUTH_ENABLED` | `true` | Enable API key authentication |
| `SYFTER_ADMIN_API_KEY` | -- | Seed key for initial admin access |
| `SYFTER_AUTH_CACHE_TTL` | `60` | Auth validation cache TTL (seconds) |
| `SYFTER_RATE_LIMIT_ENABLED` | `true` | Enable per-key rate limiting |
| `SYFTER_RATE_LIMIT_QUERY` | `60` | Query requests per minute per key |
| `SYFTER_RATE_LIMIT_QUERY_BURST` | `20` | Query burst allowance |
| `SYFTER_RATE_LIMIT_UPLOAD` | `10` | Upload requests per minute per key |
| `SYFTER_RATE_LIMIT_UPLOAD_BURST` | `5` | Upload burst allowance |
| `SYFTER_CACHE_STATS_TTL` | `300` | Stats cache TTL (seconds) |
| `SYFTER_CACHE_PRODUCTS_TTL` | `300` | Products cache TTL (seconds) |

Set `SYFTER_AUTH_ENABLED=false` for local development without keys.

## Database Indexes

For large-scale deployments (1M+ packages), these indexes are critical:

```sql
-- LIKE prefix queries + ORDER BY (the COLLATE "C" is essential)
CREATE INDEX idx_package_name_c ON packages (name COLLATE "C");

-- LIKE via text_pattern_ops (used by the index scan filter)
CREATE INDEX idx_package_name_pattern ON packages (name text_pattern_ops);

-- Foreign key lookups for product-scoped counts
CREATE INDEX idx_packages_product_id ON packages (product_id);
CREATE INDEX idx_scan_product ON scans (product_id);

-- Dependency queries (package-scoped + type filter)
CREATE INDEX idx_dep_package_type ON dependencies (package_id, dependency_type);
```

## Deployment

This fork is designed for OpenShift/Kubernetes. The container image is built from `podman/Containerfile`.

A typical deployment includes:
- Syfter API (Deployment with oauth2-proxy sidecar for browser OIDC)
- PostgreSQL (StatefulSet)
- Keycloak (OIDC provider for browser access)
- AWS S3 via IRSA (SBOM object storage)

## Upstream PRs

| PR | Description | Status |
|----|-------------|--------|
| #3 | Remote URL scanning | Merged |
| #4 | Server-side remote scanning | Merged |
| #5 | Gzip validation fix | Merged |
| #6 | Jobs FK cleanup on scan replacement | Merged |
| #7 | API key auth support in CLI | Merged |
| #9 | CLI restructure, trace command, dependency tracking, OOM fix | Merged |
| #17 | Dependency query PK sort fix | Open |

## License

Apache License 2.0 -- same as upstream syfter.

## Credits

Based on [syfter](https://github.com/vdanen/syfter) by Vincent Danen.
