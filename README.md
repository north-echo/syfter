# Syfter

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11827/badge)](https://www.bestpractices.dev/projects/11827)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vdanen/syfter/badge)](https://scorecard.dev/viewer/?uri=github.com/vdanen/syfter)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/vdanen/syfter?sort=semver)
![PyPI release](https://img.shields.io/pypi/s/syfter)
![Downloads](https://static.pepy.tech/badge/syfter)

SBOM generation and management tool using [Syft](https://github.com/anchore/syft).

**Version: 0.9.1.0**

## Overview

Syfter wraps the Anchore Syft tool to:

- **Scan** directories of RPMs, container images, and other artifacts
- **Enrich** SBOMs with product-specific metadata (CPEs, PURLs with distro qualifiers)
- **Store** SBOMs in a queryable database (SQLite or PostgreSQL)
- **Query** packages and files across all your products or systems
- **Export** to customer-facing formats (SPDX, CycloneDX)

### Enterprise Capabilities

In addition to all standard syfter features, this release adds production-oriented server capabilities:

| Feature | Description |
|---------|-------------|
| **API key authentication** | Per-team keys with admin management (`X-API-Key` header) |
| **Rate limiting** | Token-bucket limits per key (queries and uploads per minute) |
| **Response caching** | In-process cache with auto-invalidation on mutations |
| **RPM dependency tracking** | Query requires/provides relationships at scale |
| **Cross-product tracing** | `syfter trace` follows packages across repos, base images, and layered containers |
| **Attestation metadata** | Cosign SLSA and SPDX attestation indexing |
| **Component relationships** | Product-to-product composition mappings |
| **Query performance** | Optimized PostgreSQL patterns for tens of millions of packages |

### Two Modes of Operation

Syfter supports two distinct modes:

1. **Product Mode** - Scan and manage SBOMs for software products (distros, containers, middleware)
2. **System Mode** - Scan and track packages across your infrastructure (servers, VMs, hosts)

### Two Deployment Options

Syfter can run in two deployment configurations:

| Mode | Storage | Best For |
|------|---------|----------|
| **Local Mode** | SQLite (`~/.syfter/syfter.db`) | Development, single-user, small scale |
| **Server Mode** | PostgreSQL + MinIO (S3) | Production, multi-user, large scale |

- **Local Mode** is the default - no setup required, just install and run
- **Server Mode** requires running the API server with `podman-compose`

## Prerequisites

- **Python 3.9+**
- **Syft** - Install from [GitHub releases](https://github.com/anchore/syft/releases), Homebrew, or:
  ```bash
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  ```
- **Skopeo** - Can be installed via dnf or Homebrew, see [GitHub installation instructions](https://github.com/containers/skopeo/blob/main/install.md)

## Installation

### Using uv (recommended)

```bash
# Install as a standalone CLI tool (isolated environment)
uv tool install syfter

# Or install with server components
uv tool install "syfter[server]"

# Upgrade to latest version
uv tool upgrade syfter
```

### Using pip

```bash
# Install from PyPI
pip install syfter

# Install with server components
pip install "syfter[server]"
```

### From Source

```bash
git clone https://github.com/vdanen/syfter.git
cd syfter

# Using uv
uv tool install .

# Or using pip
pip install -e .

# Install with all components (server + dev tools)
pip install -e ".[all]"
```

See [docs/BUILDING.md](docs/BUILDING.md) for detailed build and distribution options.

## Deployment Options

### Option 1: Local Mode (Default)

Local mode uses SQLite and requires no additional setup. Just install and start using:

```bash
# Scans store to ~/.syfter/syfter.db
syfter scan /path/to/rpms -p myproduct -v 1.0
syfter products
syfter query -n "openssl%"
```

Local mode is great for:
- Development and testing
- Single-user workstations
- Small to medium scan volumes (up to ~50 products)

### Option 2: Server Mode (Distributed)

Server mode uses PostgreSQL for the database and MinIO (S3-compatible) for SBOM storage. This scales to thousands of products and supports multiple concurrent users.

#### Prerequisites for Server Mode

- **Podman** and **podman-compose** (or Docker/docker-compose)
  ```bash
  # Fedora/RHEL
  sudo dnf install podman podman-compose
  
  # macOS
  brew install podman podman-compose
  ```

#### Start the Server

```bash
cd podman

# Create environment file with your passwords
cp env.example .env
# Edit .env to set secure passwords:
#   POSTGRES_PASSWORD=your_secure_password
#   MINIO_ROOT_PASSWORD=your_secure_password

# Start all services (PostgreSQL, MinIO, API)
podman-compose up -d

# Check status
podman-compose ps

# View logs
podman-compose logs -f syfter-api
```

The services will be available at:
- **API Server**: http://localhost:8000
- **MinIO Console**: http://localhost:9001 (login with MINIO_ROOT_USER/PASSWORD)
- **PostgreSQL**: localhost:5432

#### Configure the CLI for Server Mode

Set the `SYFTER_SERVER` environment variable to point to your API server:

```bash
# Add to your ~/.bashrc or ~/.zshrc
export SYFTER_SERVER=http://localhost:8000

# Or specify per-command
syfter --server http://localhost:8000 products

# Authenticated server (set your team API key)
export SYFTER_API_KEY=your-team-key
```

#### API Authentication

When `SYFTER_AUTH_ENABLED=true` (the default), all API requests require an `X-API-Key` header except `/health`.

```bash
# Start the server with a seed admin key
SYFTER_AUTH_ENABLED=true \
SYFTER_ADMIN_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
SYFTER_DB_TYPE=postgresql \
SYFTER_PG_HOST=localhost \
SYFTER_PG_PASSWORD=changeme \
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000

# Create a team key
curl -X POST http://localhost:8000/api/v1/admin/keys/ \
  -H "X-API-Key: $SYFTER_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"team_name": "security"}'

export SYFTER_API_KEY=<returned-key>
export SYFTER_SERVER=http://localhost:8000
syfter products
```

Set `SYFTER_AUTH_ENABLED=false` for local development without API keys.

#### Server Mode Commands

Once `SYFTER_SERVER` is set, all commands automatically use the server:

```bash
# These now talk to the API server
syfter scan registry.redhat.io/ubi9:latest -p ubi -v 9.0
syfter products
syfter query -n "kernel%"
syfter export -p ubi -v 9.0 -f spdx-json -o ubi9.spdx.json
```

#### Force Local Mode

If `SYFTER_SERVER` is set but you want to use local SQLite:

```bash
syfter --local products
```

#### Server Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      syfter CLI (client)                        │
│               SYFTER_SERVER=http://localhost:8000               │
└───────────────────────────────┬─────────────────────────────────┘
                                │ HTTP API
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Syfter API Server                          │
│                    (FastAPI, syfter-api)                        │
└───────────────────────────────┬─────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌─────────────────────┐              ┌─────────────────────┐
│     PostgreSQL      │              │   MinIO (S3)        │
│  (syfter-postgres)  │              │  (syfter-minio)     │
│                     │              │                     │
│  • Products         │              │  • Original SBOMs   │
│  • Packages         │              │  • Modified SBOMs   │
│  • Files            │              │  (gzip compressed)  │
│  • Systems          │              │                     │
└─────────────────────┘              └─────────────────────┘
```

#### Managing the Server

```bash
cd podman

# Stop all services
podman-compose down

# Stop and remove volumes (DELETES ALL DATA)
podman-compose down -v

# Rebuild after code changes
podman-compose build --no-cache api
podman-compose up -d api

# View API logs
podman-compose logs -f syfter-api

# Access PostgreSQL directly
podman-compose exec syfter-postgres psql -U syfter -d syfter
```

#### ARM Mac Users

On Apple Silicon Macs, you may need to specify the platform:

```bash
# Option 1: Set in .env
echo "DOCKER_DEFAULT_PLATFORM=linux/arm64" >> .env

# Option 2: Set environment variable
export DOCKER_DEFAULT_PLATFORM=linux/arm64
podman-compose up -d
```

## Quick Start

### 1. Scan a Directory of RPMs

```bash
# Scan RHEL 10.0 packages
syfter scan /path/to/rhel10/rpms -p rhel -v 10.0

# Scan with description
syfter scan /path/to/rpms -p rhel -v 10.0 --description "Red Hat Enterprise Linux 10.0"
```

### 2. Scan a Container Image

```bash
syfter scan registry.redhat.io/rhel9:latest -p rhel -v 9.0
syfter scan docker:ubi9/ubi:latest -p ubi -v 9.0
```

#### Registry Authentication

Many container registries (like `registry.redhat.io`) require authentication. Syfter uses your local container credentials, so log in before scanning:

```bash
# Red Hat Registry (requires Red Hat account)
podman login registry.redhat.io

# Quay.io (for private repos)
podman login quay.io

# Generic registry
podman login myregistry.example.com
```

Credentials are stored in `~/.config/containers/auth.json` (or `$XDG_RUNTIME_DIR/containers/auth.json`) and are used automatically by both `podman` and `skopeo`.

**For Red Hat Registry access:**
1. Create a free account at [access.redhat.com](https://access.redhat.com)
2. Or use a service account token from the [Red Hat Registry Service Accounts](https://access.redhat.com/terms-based-registry/) page

```bash
# Using service account (non-interactive)
podman login registry.redhat.io \
  --username "12345678|myserviceaccount" \
  --password-stdin < token.txt
```

**Verify authentication:**
```bash
# Check if you can access the registry
skopeo inspect --override-arch amd64 --override-os linux \
  docker://registry.redhat.io/ubi9/ubi:latest | jq '.Name'
```

#### Linux Signature Lookaside Configuration

On RHEL/Fedora systems, skopeo is configured to fetch image signatures from Red Hat's signature store via `/etc/containers/registries.d/registry.redhat.io.yaml`:

```yaml
docker:
  registry.redhat.io:
    lookaside: https://registry.redhat.io/containers/sigstore
```

This causes skopeo to fetch signatures when pulling images. When copying to OCI directory format (which syfter uses internally), skopeo would fail because OCI directories can't store signatures:

```
FATA[0002] Can not copy signatures to oci:/tmp/...: Pushing signatures for OCI images is not supported
```

Syfter handles this automatically by using `--remove-signatures` when copying images. This only affects what gets written to the temporary OCI directory - it doesn't disable signature validation. If your `policy.json` requires signature verification, that still happens during the pull; the signatures just aren't copied to the local destination.

**Note:** macOS systems typically don't have this registry configuration (brew-installed skopeo doesn't include it), so this issue only appears on Linux.

#### Container Layer Tracking

When scanning container images, syfter **automatically** determines which base image contributed each package. This helps identify where to fix vulnerabilities in multi-stage container builds.

```bash
# Scan a container image - base image scanning is automatic
syfter scan registry.redhat.io/rhel9/go-toolset:latest -p go-toolset -v 9.0

# Query packages - shows source image for each package
syfter query -n "go%" -p go-toolset -v 9.0
```

Output shows which image each package came from:
```
  Name                    Version          Product          Source Image      
 ──────────────────────────────────────────────────────────────────────────── 
  bash                    5.1.8-9.el9      go-toolset-9.0   ubi9/ubi          
  git                     2.47.3-1.el9_6   go-toolset-9.0   ubi9/s2i-base     
  golang                  1.25.3-1.el9_7   go-toolset-9.0   rhel9/go-toolset  
```

**How it works:**
1. Uses **layer digest comparison** to accurately identify the base image chain (e.g., `ubi9/ubi` → `ubi9/s2i-core` → `ubi9/s2i-base` → `rhel9/go-toolset`)
2. Extracts exact image references from labels (e.g., `registry.redhat.io/ubi9/ubi:9.7-1767674301`)
3. Scans each base image to build package lists
4. Compares package lists to determine which image introduced each package
5. Records `source_image` with each package in the database

The `syfter layers` command shows the complete layer chain with:
- `layer_id`: The container layer digest (truncated)
- `layer_index`: The position in the layer stack (0 = base layer)
- `source_image`: The image that introduced this layer
- `image_reference`: The full image reference (registry/name:version-release)

### 3. Query Packages

```bash
# Find all kernel packages across products
syfter query -n "kernel%"

# Find packages in a specific product
syfter query -n "openssl%" -p rhel -v 10.0

# Find files
syfter query -f "%/bin/bash"
```

### 4. Export SBOMs

```bash
# Export to SPDX JSON
syfter export -p rhel -v 10.0 -f spdx-json -o rhel-10.spdx.json

# Export to CycloneDX
syfter export -p rhel -v 10.0 -f cyclonedx-json -o rhel-10.cdx.json

# Export to all formats
syfter export -p rhel -v 10.0 -f all -o ./sboms/
```

## System Mode (Infrastructure Scanning)

In addition to scanning products, Syfter can scan hosts in your infrastructure to track installed packages across systems.

> **Note:** System mode requires server mode (`SYFTER_SERVER` must be set). See [Server Mode](#option-2-server-mode-distributed) setup instructions.

### Scan the Local Host

```bash
# Scan localhost and upload to server
syfter system-scan

# Add a tag for grouping
syfter system-scan --tag production

# Scan with a descriptive tag
syfter system-scan --tag "web-servers"
```

### Scan Remote Hosts via SSH

```bash
# Scan a remote host
syfter system-scan webserver01.example.com

# With SSH options
syfter system-scan 192.168.1.100 -u admin -i ~/.ssh/server_key

# Scan with a tag
syfter system-scan dbserver.local --tag databases
```

**Note:** Remote scanning requires `syft` to be installed on the remote host.

### List Systems

```bash
# List all scanned systems
syfter systems

# Filter by tag
syfter systems --tag production
```

### Query Packages Across Systems

```bash
# Find which systems have openssh installed
syfter system-query -n "openssh%"

# Search in specific systems
syfter system-query -n "kernel%" --tag production

# Find files across systems
syfter system-query -f "%/bin/bash"
```

### List Packages/Files for a System

```bash
# List all packages on a system
syfter system-list -H webserver01 -t packages

# List all files
syfter system-list -H webserver01 -t files
```

## CLI Reference

### `syfter scan`

Scan a target and store the SBOM with product metadata.

```
Usage: syfter scan [OPTIONS] TARGET

Options:
  -p, --product TEXT        Product name (required)
  -v, --version TEXT        Product version (required)
  --vendor TEXT             Vendor name (default: "Red Hat")
  --cpe-vendor TEXT         CPE vendor string (default: "redhat")
  --purl-namespace TEXT     PURL namespace (default: "redhat")
  --description TEXT        Product description
  -o, --output PATH         Write modified SBOM to file
  --original-output PATH    Write original SBOM to file
  --no-store                Don't store in database
```

### `syfter search` (alias: `query`)

Search packages and files across all products.

```
Usage: syfter search [OPTIONS]

Options:
  -n, --name TEXT           Package name pattern (% = wildcard)
  -f, --file TEXT           File path pattern
  -d, --digest TEXT         File digest (exact match)
  -p, --product TEXT        Filter by product name
  -v, --version TEXT        Filter by product version
  --limit INTEGER           Maximum results (default: 50)
  --json                    Output as JSON
  --cross-product           Trace package across the full product stack (server mode)
```

The `query` command name is deprecated but still accepted.

### `syfter trace`

Trace a package across the product stack (RHEL repos, UBI base images, layered containers). Requires server mode.

```
Usage: syfter trace [OPTIONS] PACKAGE_NAME

Options:
  --pkg-version TEXT        Package version filter
  --limit INTEGER           Maximum results per category (default: 200)
  --json                    Output as JSON
```

### `syfter deps`

Query RPM dependency relationships (requires server mode with indexed dependencies).

```
Usage: syfter deps [OPTIONS] [DEPENDENCY_NAME]

Options:
  --package TEXT            Filter by package name
  --type [requires|provides]  Dependency type (default: requires)
  -p, --product TEXT        Filter by product name
  -v, --version TEXT        Filter by product version
  --limit INTEGER           Maximum results (default: 50)
  --json                    Output as JSON
```

### `syfter relationships`

List component relationships between products (server mode).

```
Usage: syfter relationships [OPTIONS]

Options:
  --limit INTEGER           Maximum results (default: 50)
  --json                    Output as JSON
```

### `syfter export`

Export a product's SBOM to various formats.

```
Usage: syfter export [OPTIONS]

Options:
  -p, --product TEXT        Product name (required)
  -v, --version TEXT        Product version (required)
  -f, --format TEXT         Output format: syft-json, spdx-json, spdx-tv,
                            cyclonedx-json, cyclonedx-xml, all
  -o, --output PATH         Output file or directory
```

### `syfter products`

List all products in the database.

### `syfter scans`

List all scans, optionally filtered by product.

### `syfter stats`

Show database statistics.

### `syfter check`

Verify syft is installed and show its version.

### `syfter list`

List files or packages for a product version.

```
Usage: syfter list [OPTIONS]

Options:
  -p, --product TEXT        Product name (required)
  -v, --version TEXT        Product version (required)
  -t, --type [files|packages]  What to list (default: files)
  --full                    Include architecture in package output
  --layers                  Include source layer (container scans only)
```

With `--layers`, packages are output as `source_image::package-version`:

```bash
syfter list -p go-toolset -v 1.25 -t packages --layers | grep zlib
ubi9/ubi::zlib-1.2.11-40.el9
ubi9/s2i-base::zlib-devel-1.2.11-40.el9

# Find all packages from a specific base image
syfter list -p go-toolset -v 1.25 -t packages --layers | grep "^ubi9/ubi::"

# Count packages per layer
syfter list -p go-toolset -v 1.25 -t packages --layers | cut -d: -f1 | sort | uniq -c
```

### `syfter layers`

Display container layer chain for a product (container scans only).

```
Usage: syfter layers [OPTIONS]

Options:
  -p, --product TEXT        Product name (required)
  -v, --version TEXT        Product version (required)
  --json                    Output as JSON
```

Shows the layer-by-layer breakdown of a container image, including:
- Layer index and truncated digest
- Source image name (e.g., `ubi9/ubi`, `rhel9/go-toolset`)
- Version and full image reference for each layer

### `syfter system-scan`

Scan a host and store the SBOM for infrastructure tracking.

```
Usage: syfter system-scan [OPTIONS] [TARGET]

Arguments:
  TARGET                    Hostname or IP (default: localhost)

Options:
  -t, --tag TEXT            Tag for grouping/CMDB linking
  -u, --user TEXT           SSH user for remote hosts
  -p, --port INTEGER        SSH port (default: 22)
  -i, --identity PATH       SSH identity file
  -o, --output PATH         Write SBOM to file
  --no-store                Don't store (just output)
  -q, --quiet               Suppress progress output
  --skip-files              Skip file indexing
  --include-debug           Include debuginfo packages
```

### `syfter systems`

List all systems in the database.

```
Usage: syfter systems [OPTIONS]

Options:
  --tag TEXT                Filter by system tag
```

### `syfter system-query`

Query packages and files across systems.

```
Usage: syfter system-query [OPTIONS]

Options:
  -n, --name TEXT           Package name pattern (% = wildcard)
  -f, --file TEXT           File path pattern
  -d, --digest TEXT         File digest (exact match)
  -H, --hostname TEXT       Filter by hostname
  -t, --tag TEXT            Filter by system tag
  --limit INTEGER           Maximum results (default: 50)
  --json                    Output as JSON
```

### `syfter system-list`

List files or packages for a specific system.

```
Usage: syfter system-list [OPTIONS]

Options:
  -H, --hostname TEXT       System hostname (required)
  -t, --type [files|packages]  What to list (default: files)
  --full                    Include architecture in package output
```

## Shell Script Wrappers

For convenience, shell scripts are provided in `scripts/`:

```bash
# Simple scan wrapper
./scripts/scan-product.sh /path/to/rpms rhel 10.0

# Query wrapper
./scripts/query.sh package "kernel%"
./scripts/query.sh file "%/bin/bash"

# Export wrapper
./scripts/export-sbom.sh rhel 10.0 spdx-json rhel-10.spdx.json

# Batch scan from config file
./scripts/batch-scan.sh products.conf
```

### Batch Scan Configuration

Create a config file for batch scanning:

```
# products.conf
/path/to/rhel10 rhel 10.0 "RHEL 10.0"
/path/to/rhel9 rhel 9.4 "RHEL 9.4"
/path/to/ocp openshift 4.14 "OpenShift Container Platform 4.14"
registry.redhat.io/ubi9:latest ubi 9.0 "Universal Base Image 9"
```

Then run:
```bash
./scripts/batch-scan.sh products.conf
```

## How It Works

### SBOM Enrichment

When you scan a target, Syfter:

1. Runs Syft to generate a `syft-json` format SBOM
2. Modifies each package's metadata to include:
   - **CPE**: Updated with vendor (e.g., `cpe:2.3:a:redhat:kernel:...`)
   - **PURL**: Added distro qualifier (e.g., `pkg:rpm/redhat/kernel@5.14?distro=rhel-10.0`)
   - **Metadata**: Product information for traceability

### Storage

Syfter stores data in two locations:

**Local Mode** (SQLite):
- Database: `~/.syfter/syfter.db`
- SBOMs stored as compressed blobs in the database

**Server Mode** (PostgreSQL + MinIO):
- Database: PostgreSQL for indexed metadata (packages, files, products)
- Object Storage: MinIO/S3 for compressed SBOM files

Both modes store:
- **Full SBOM preservation**: Both original and modified syft-json stored as-is
- **Indexed packages**: Package metadata for fast querying
- **Indexed files**: File paths and digests for lookup
- **Container layers**: Layer-to-image mapping for container scans

This dual approach allows:
- Fast queries across all products (database)
- Pristine SBOM retrieval for export (object storage)

### Export Formats

Syfter uses Syft's native conversion to generate:

| Format | Extension | Description |
|--------|-----------|-------------|
| `syft-json` | `.syft.json` | Native Syft format (stored internally) |
| `spdx-json` | `.spdx.json` | SPDX 2.3 JSON |
| `spdx-tv` | `.spdx` | SPDX Tag-Value |
| `cyclonedx-json` | `.cdx.json` | CycloneDX 1.4 JSON |
| `cyclonedx-xml` | `.cdx.xml` | CycloneDX 1.4 XML |

## Environment Variables

### Client Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SYFTER_DB` | SQLite database path (local mode) | `~/.syfter/syfter.db` |
| `SYFTER_SERVER` | API server URL (server mode) | None (uses local mode) |

### Server Variables (for API container)

| Variable | Description | Default |
|----------|-------------|---------|
| `SYFTER_DB_TYPE` | Database type (`sqlite` or `postgresql`) | `sqlite` |
| `SYFTER_PG_HOST` | PostgreSQL host | `localhost` |
| `SYFTER_PG_PORT` | PostgreSQL port | `5432` |
| `SYFTER_PG_DATABASE` | PostgreSQL database name | `syfter` |
| `SYFTER_PG_USER` | PostgreSQL username | `syfter` |
| `SYFTER_PG_PASSWORD` | PostgreSQL password | (required) |
| `SYFTER_STORAGE_TYPE` | Storage type (`local` or `s3`) | `local` |
| `SYFTER_S3_ENDPOINT` | S3/MinIO endpoint URL | (required for s3) |
| `SYFTER_S3_BUCKET` | S3 bucket name | `syfter-sboms` |
| `SYFTER_S3_ACCESS_KEY` | S3 access key | (required for s3) |
| `SYFTER_S3_SECRET_KEY` | S3 secret key | (required for s3) |
| `SYFTER_API_KEY` | Client API key (server mode) | None |
| `SYFTER_AUTH_ENABLED` | Enable API key authentication | `true` |
| `SYFTER_ADMIN_API_KEY` | Seed key for initial admin access | None |
| `SYFTER_AUTH_CACHE_TTL` | Auth validation cache TTL (seconds) | `60` |
| `SYFTER_RATE_LIMIT_ENABLED` | Enable per-key rate limiting | `true` |
| `SYFTER_RATE_LIMIT_QUERY` | Query requests per minute per key | `60` |
| `SYFTER_RATE_LIMIT_QUERY_BURST` | Query burst allowance | `20` |
| `SYFTER_RATE_LIMIT_UPLOAD` | Upload requests per minute per key | `10` |
| `SYFTER_RATE_LIMIT_UPLOAD_BURST` | Upload burst allowance | `5` |
| `SYFTER_CACHE_STATS_TTL` | Stats cache TTL (seconds) | `300` |
| `SYFTER_CACHE_PRODUCTS_TTL` | Products cache TTL (seconds) | `300` |

## Database Indexes (Large Scale)

For deployments with 1M+ packages, these PostgreSQL indexes are critical for query performance:

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

## Examples

### Workflow: Generating Customer SBOMs

```bash
# 1. Scan all your products
syfter scan /mnt/rhel10-rpms -p rhel -v 10.0
syfter scan /mnt/rhel9-rpms -p rhel -v 9.4
syfter scan registry.redhat.io/ubi9:latest -p ubi -v 9.0

# 2. Check what's stored
syfter products
syfter stats

# 3. Query across all products
syfter query -n "openssl%"

# 4. Export customer-facing SBOMs
mkdir -p customer-sboms
syfter export -p rhel -v 10.0 -f all -o customer-sboms/
syfter export -p rhel -v 9.4 -f spdx-json -o customer-sboms/rhel-9.4.spdx.json
```

### Workflow: Finding Package Locations

```bash
# Find which products contain a specific package
syfter query -n "curl" --json | jq '.[] | {product: "\(.product_name)-\(.product_version)", version: .version}'

# Find files by path pattern
syfter query -f "%libssl%"

# Find files by digest
syfter query -d "sha256:abc123..."
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                               syfter CLI                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────┐    ┌─────────────┐    ┌─────────────────────────┐   │
│  │      Scanner      │───>│ Manipulator │───>│        Storage          │   │
│  │  (syft, ssh+syft) │    │ (CPE/PURL)  │    │ (SQLite/PostgreSQL+S3)  │   │
│  └───────────────────┘    └─────────────┘    └───────────┬─────────────┘   │
│          │                                               │                  │
│          │                                               v                  │
│  ┌───────┴───────┐                              ┌──────────┐               │
│  │ Scan Targets  │                              │ Exporter │               │
│  ├───────────────┤                              │  (SPDX/  │               │
│  │ • Products    │                              │   CDX)   │               │
│  │   - RPM dirs  │                              └──────────┘               │
│  │   - Containers│                                                         │
│  │   - Archives  │                                                         │
│  │ • Systems     │                                                         │
│  │   - Localhost │                                                         │
│  │   - SSH hosts │                                                         │
│  └───────────────┘                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Building and Distribution

See [docs/BUILDING.md](docs/BUILDING.md) for instructions on:
- Building Python wheels for distribution
- Creating container images
- Building RPM packages
- Offline installation bundles

## Deployment

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production deployment guidance including:
- Server architecture
- PostgreSQL setup
- MinIO/S3 configuration
- systemd service files
- Security considerations

For OpenShift/Kubernetes deployments, the API container image is built from `podman/Containerfile`. A typical production stack includes the Syfter API (often with an oauth2-proxy sidecar for browser OIDC), PostgreSQL, and S3-compatible object storage (MinIO or AWS S3 via IRSA).

## Understanding Container Layers

See [docs/MULTI-STAGE-BUILDS.md](docs/MULTI-STAGE-BUILDS.md) for details on:
- How syfter handles multi-stage Docker/Podman builds
- Why build-stage layers don't appear in final images
- Understanding Go module detection in compiled binaries
- File search limitations for non-package-managed files

## Development

```bash
# Install development dependencies
pip install -e ".[all]"

# Run tests
./scripts/run-tests.sh local      # Local SQLite tests
./scripts/run-tests.sh coverage   # With coverage report
./scripts/run-tests.sh server     # Server tests (requires running server)

# Format code
black syfter/
ruff check syfter/
```

## Credits

[syfter](https://github.com/vdanen/syfter) by Vincent Danen, with contributions from Red Hat Product Security.

## License

Apache License 2.0

## Vibe Coding Notice

In all transparency, this code was almost entirely written with AI.  While
I can program in Python, I didn't really have the time to do it so
leveraged AI for it.  If there are issues (and there probably are!) feel
free to create a PR with a fix.  The intent behind this project was to
create something _quickly_ that would solve some challenges around the
production and use of SBOMs.  It's very complicated which is why it
leverages [Syft](https://github.com/anchore/syft) (why reinvent the
wheel?).

If using AI generated is scary or offensive, there are probably other
things you can use.  If it isn't, this may solve the challenges you have
that it's solving for me.
