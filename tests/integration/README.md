# Integration Tests

Live-server tests against a running Syfter deployment.

## Auth model for CI (API key only — no OIDC)

**OIDC access tokens are short-lived** (typically 5–60 minutes). CI should use a **long-lived Syfter API key** fetched from Vault via GitLab's `secrets:` keyword (same pattern as [lightwell-osidb](https://gitlab.cee.redhat.com/lightwell/lightwell-osidb/-/blob/main/.gitlab-ci.yml) and [lightwell/syfter](https://gitlab.cee.redhat.com/lightwell/syfter)).

### Two URLs per environment

| Route | Stage | Auth |
|-------|-------|------|
| **CLI** (pytest, CI, `syfter` CLI) | `https://syfter-cli.stage.lightwell.redhat.com` | **`X-API-Key` only** |
| **Browser** (dashboard) | `https://syfter.stage.lightwell.redhat.com` | oauth2-proxy + Keycloak |

Prod CLI: `https://syfter-cli.lightwell.redhat.com`

## Vault secrets (GitLab CI)

Place secrets in Vault on mount `apps`, path `lightwell/syfter/stage/testing`:

| Secret | Vault reference | Field | Used for |
|--------|-----------------|-------|----------|
| Team API key | `lightwell/syfter/stage/testing/api-key@apps` | `api-key` | CI default suite (`SYFTER_API_KEY`) |
| Admin API key | `lightwell/syfter/stage/testing/admin-key@apps` | `admin-key` | Admin/auth tests (`SYFTER_ADMIN_API_KEY`) |

The admin key is the cluster admin credential (same class as deploy's `lightwell/syfter/stage/admin/api_key@apps`), stored alongside the team key for integration testing.

Example `.gitlab-ci.yml` fragment (see `.gitlab-ci.yml.example`):

```yaml
variables:
  VAULT_AUTH_PATH: gitlabcee
  VAULT_SERVER_URL: https://vault.corp.redhat.com:8200
  VAULT_AUTH_ROLE: jwt-gitlabcee-lightwell-syfter-SOURCE-XXXXX  # your project's JWT role
  SYFTER_TEST_SERVER: "https://syfter-cli.stage.lightwell.redhat.com"

default:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.corp.redhat.com:8200

integration-tests:stage:
  secrets:
    SYFTER_API_KEY_PATH:
      vault: lightwell/syfter/stage/testing/api-key@apps
    SYFTER_ADMIN_API_KEY_PATH:
      vault: lightwell/syfter/stage/testing/admin-key@apps
  before_script:
    - pip install -e ".[all]"
    - export SYFTER_API_KEY="$(tr -d '\n' < "${SYFTER_API_KEY_PATH}")"
    - export SYFTER_ADMIN_API_KEY="$(tr -d '\n' < "${SYFTER_ADMIN_API_KEY_PATH}")"
  script:
    - pytest tests/integration/ -m "integration and not auth" -v
```

GitLab injects `*_PATH` variables as **file paths** (default `file: true`), matching how `lightwell/syfter` deploy jobs read secrets.

### Vault setup checklist

1. Bootstrap both secrets (see below).
2. Ensure the GitLab JWT role (`VAULT_AUTH_ROLE`) for this repo can read both paths.
3. Do **not** commit keys; do **not** use GitLab CI/CD masked variables for them if Vault is the source of truth.

## Bootstrap: fetch admin key and create team API key

One-time setup before CI can run.

### Step 1 — Fetch the admin key

Pick one source:

**A. OpenShift cluster** (most common for first-time setup):

```bash
export SYFTER_ADMIN_API_KEY="$(
  oc -n lightwell--runtime-syfter get secret syfter-admin-key \
    -o jsonpath='{.data.api-key}' | base64 -d
)"
```

**B. Deploy Vault path** (if you have read access to the deploy secret):

```bash
export VAULT_ADDR=https://vault.corp.redhat.com:8200
vault login -method=oidc   # or your usual auth

export SYFTER_ADMIN_API_KEY="$(
  vault kv get -field=api_key apps/lightwell/syfter/stage/admin
)"
```

**C. Testing Vault** (after step 2 below):

```bash
export SYFTER_ADMIN_API_KEY="$(
  vault kv get -field=admin-key apps/lightwell/syfter/stage/testing
)"
```

Verify the admin key works:

```bash
export SYFTER_TEST_SERVER=https://syfter-cli.stage.lightwell.redhat.com

curl -sS -H "X-API-Key: ${SYFTER_ADMIN_API_KEY}" \
  "${SYFTER_TEST_SERVER}/api/v1/admin/keys/" | jq 'length'
```

### Step 2 — Store admin key in testing Vault

```bash
vault kv put apps/lightwell/syfter/stage/testing \
  admin-key="${SYFTER_ADMIN_API_KEY}"
```

If the path already has other fields (e.g. `api-key`), use `vault kv patch` instead:

```bash
vault kv patch apps/lightwell/syfter/stage/testing \
  admin-key="${SYFTER_ADMIN_API_KEY}"
```

### Step 3 — Create the team API key for CI

Generate a dedicated **team** key (not admin):

```bash
export SYFTER_TEST_SERVER=https://syfter-cli.stage.lightwell.redhat.com

export SYFTER_API_KEY="$(
  curl -sS -X POST "${SYFTER_TEST_SERVER}/api/v1/admin/keys/" \
    -H "X-API-Key: ${SYFTER_ADMIN_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
      "team_name": "gitlab-ci",
      "description": "GitLab CI integration tests — destructive inttest-* data",
      "expires_in_days": 365
    }' | jq -r .api_key
)"
```

The response includes the full key only once. Save it now.

### Step 4 — Store team key in testing Vault

```bash
vault kv patch apps/lightwell/syfter/stage/testing \
  api-key="${SYFTER_API_KEY}"
```

Verify:

```bash
curl -sS -H "X-API-Key: ${SYFTER_API_KEY}" \
  "${SYFTER_TEST_SERVER}/api/v1/query/stats" | jq .
```

## Run locally

```bash
export SYFTER_TEST_SERVER=https://syfter-cli.stage.lightwell.redhat.com
export SYFTER_API_KEY="$(vault kv get -field=api-key apps/lightwell/syfter/stage/testing)"

pytest tests/integration/ -m integration -v
./scripts/run-tests.sh integration
```

### Admin-key tests

Some tests require the **admin** key (`SYFTER_ADMIN_API_KEY` from `admin-key@apps`), not the team key:

| Module | Marker | Endpoints |
|--------|--------|-----------|
| `test_admin.py` | `integration`, `auth` | `GET/POST/DELETE /api/v1/admin/keys/`, access log |
| `test_validation.py` (`TestAdminValidation`) | `integration`, `auth` | Admin validation (422 on bad input) |

CI runs the default suite with `-m "integration and not auth"` (team key only). Admin tests run separately on the default branch via `-m "integration and auth"` once `admin-key@apps` is populated.

```bash
export SYFTER_ADMIN_API_KEY="$(vault kv get -field=admin-key apps/lightwell/syfter/stage/testing)"
pytest tests/integration/ -m "integration and auth" -v
```

## Destructive data

Tests create `inttest-*` products/systems and delete them on teardown.

## OpenAPI

Public `/openapi.json` is OAuth-gated. Contract tests should use a locally generated spec from the FastAPI app.
