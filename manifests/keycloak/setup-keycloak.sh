#!/bin/bash
#
# Keycloak Setup for Syfter
#
# Deploys Keycloak on the ROSA cluster and configures it as the OIDC
# provider for the syfter OAuth proxy (browser access on port 4443).
# API key auth on port 8080 is unaffected.
#
# Usage:
#   ./manifests/keycloak/setup-keycloak.sh deploy     # Full deploy + configure
#   ./manifests/keycloak/setup-keycloak.sh status      # Check Keycloak status
#   ./manifests/keycloak/setup-keycloak.sh create-user # Create a Keycloak user
#   ./manifests/keycloak/setup-keycloak.sh teardown    # Remove Keycloak

set -euo pipefail

NAMESPACE=syfter
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REALM=syfter
CLIENT_ID=syfter-api
CREDS_FILE="$SCRIPT_DIR/.keycloak-creds"

# ─── Helpers ───────────────────────────────────────────────────────────────────

info()  { echo "→ $*"; }
ok()    { echo "✓ $*"; }
fail()  { echo "✗ $*" >&2; exit 1; }

check_logged_in() {
    oc whoami &>/dev/null || fail "Not logged in to OpenShift. Run: oc login"
}

get_kc_url() {
    local host
    host=$(oc get route keycloak -n "$NAMESPACE" -o jsonpath='{.spec.host}' 2>/dev/null) \
        || fail "Keycloak route not found"
    echo "https://$host"
}

get_admin_password() {
    if [[ -f "$CREDS_FILE" ]]; then
        grep '^KC_ADMIN_PASSWORD=' "$CREDS_FILE" | cut -d= -f2
    else
        oc get secret keycloak-credentials -n "$NAMESPACE" \
            -o jsonpath='{.data.KC_ADMIN_PASSWORD}' 2>/dev/null | base64 -d
    fi
}

get_admin_token() {
    local kc_url="$1" password="$2"
    curl -sf "$kc_url/realms/master/protocol/openid-connect/token" \
        -d "client_id=admin-cli" \
        -d "username=admin" \
        -d "password=$password" \
        -d "grant_type=password" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
}

get_syfter_route() {
    oc get route syfter-api -n "$NAMESPACE" -o jsonpath='{.spec.host}' 2>/dev/null \
        || fail "Syfter route not found"
}

# ─── Step 1: Create keycloak database in existing PostgreSQL ───────────────────

create_database() {
    info "Creating keycloak database in existing PostgreSQL..."

    local pg_pod
    pg_pod=$(oc get pod -n "$NAMESPACE" -l app=syfter-db -o jsonpath='{.items[0].metadata.name}')
    [[ -n "$pg_pod" ]] || fail "PostgreSQL pod not found"

    local kc_db_password="$1"

    # Connect as the syfter user (database owner) and create keycloak DB
    # The Red Hat PostgreSQL container grants CREATEDB to POSTGRESQL_USER
    oc exec -n "$NAMESPACE" "$pg_pod" -- bash -c "
        # Check if keycloak database already exists
        if psql -U syfter -d syfter -tAc \"SELECT 1 FROM pg_database WHERE datname='keycloak'\" | grep -q 1; then
            echo 'Database keycloak already exists'
        else
            # Try creating as syfter user first
            createdb -U syfter keycloak 2>/dev/null && echo 'Created database keycloak' || {
                echo 'syfter user cannot createdb, trying psql workaround...'
                psql -U syfter -d syfter -c 'CREATE DATABASE keycloak;' 2>/dev/null \
                    && echo 'Created database keycloak' \
                    || echo 'ERROR: Cannot create database. May need POSTGRESQL_ADMIN_PASSWORD set.'
            }
        fi

        # Create keycloak user if it doesn't exist
        psql -U syfter -d syfter -tAc \"SELECT 1 FROM pg_roles WHERE rolname='keycloak'\" | grep -q 1 || {
            psql -U syfter -d syfter -c \"CREATE USER keycloak WITH PASSWORD '$kc_db_password';\" 2>/dev/null \
                && echo 'Created user keycloak' \
                || echo 'WARN: Could not create keycloak user, will use syfter user'
        }

        # Grant privileges
        psql -U syfter -d keycloak -c 'GRANT ALL ON SCHEMA public TO keycloak;' 2>/dev/null || true
        psql -U syfter -d keycloak -c 'GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;' 2>/dev/null || true
    "
    ok "Database setup done"
}

# ─── Step 2: Create secrets ────────────────────────────────────────────────────

create_secrets() {
    local kc_db_password="$1"
    local kc_admin_password="$2"

    info "Creating Keycloak credentials secret..."
    oc create secret generic keycloak-credentials \
        --from-literal=KC_DB_USERNAME=keycloak \
        --from-literal=KC_DB_PASSWORD="$kc_db_password" \
        --from-literal=KC_ADMIN_PASSWORD="$kc_admin_password" \
        -n "$NAMESPACE" --dry-run=client -o yaml | oc apply -f -
    ok "Secret keycloak-credentials created"
}

# ─── Step 3: Deploy Keycloak ──────────────────────────────────────────────────

deploy_keycloak() {
    info "Applying Keycloak manifests..."
    oc apply -f "$SCRIPT_DIR/deployment.yaml"
    oc apply -f "$SCRIPT_DIR/service.yaml"
    oc apply -f "$SCRIPT_DIR/route.yaml"
    oc apply -f "$SCRIPT_DIR/networkpolicy.yaml"
    ok "Keycloak manifests applied"

    info "Waiting for Keycloak to be ready (this takes ~60s)..."
    if ! oc rollout status deployment/keycloak -n "$NAMESPACE" --timeout=180s; then
        echo ""
        echo "Keycloak is taking longer than expected. Check logs:"
        echo "  oc logs deployment/keycloak -n syfter"
        fail "Keycloak deployment timed out"
    fi
    ok "Keycloak is running"
}

# ─── Step 4: Configure realm + client via REST API ────────────────────────────

configure_keycloak() {
    local kc_url kc_admin_password token syfter_host

    kc_url=$(get_kc_url)
    kc_admin_password=$(get_admin_password)
    syfter_host=$(get_syfter_route)

    info "Getting admin token from $kc_url ..."

    # Keycloak may need a moment after readiness probe passes
    local retries=0
    while ! token=$(get_admin_token "$kc_url" "$kc_admin_password") 2>/dev/null; do
        retries=$((retries + 1))
        [[ $retries -lt 12 ]] || fail "Cannot get admin token after 60s"
        sleep 5
    done
    ok "Admin token acquired"

    # Create realm
    info "Creating realm '$REALM'..."
    local realm_status
    realm_status=$(curl -s -o /dev/null -w '%{http_code}' \
        "$kc_url/admin/realms" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "{
            \"realm\": \"$REALM\",
            \"enabled\": true,
            \"registrationAllowed\": true,
            \"registrationEmailAsUsername\": true,
            \"loginWithEmailAllowed\": true,
            \"duplicateEmailsAllowed\": false,
            \"sslRequired\": \"external\",
            \"displayName\": \"Syfter\"
        }")

    if [[ "$realm_status" == "201" ]]; then
        ok "Realm '$REALM' created"
    elif [[ "$realm_status" == "409" ]]; then
        ok "Realm '$REALM' already exists"
    else
        fail "Failed to create realm (HTTP $realm_status)"
    fi

    # Create client
    info "Creating OIDC client '$CLIENT_ID'..."
    local client_status
    client_status=$(curl -s -o /dev/null -w '%{http_code}' \
        "$kc_url/admin/realms/$REALM/clients" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "{
            \"clientId\": \"$CLIENT_ID\",
            \"enabled\": true,
            \"protocol\": \"openid-connect\",
            \"publicClient\": false,
            \"standardFlowEnabled\": true,
            \"directAccessGrantsEnabled\": false,
            \"serviceAccountsEnabled\": false,
            \"redirectUris\": [\"https://$syfter_host/oauth2/callback\"],
            \"webOrigins\": [\"https://$syfter_host\"]
        }")

    if [[ "$client_status" == "201" ]]; then
        ok "Client '$CLIENT_ID' created"
    elif [[ "$client_status" == "409" ]]; then
        ok "Client '$CLIENT_ID' already exists"
    else
        fail "Failed to create client (HTTP $client_status)"
    fi

    # Get client UUID and secret
    info "Retrieving client secret..."
    local client_uuid client_secret
    client_uuid=$(curl -sf "$kc_url/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
        -H "Authorization: Bearer $token" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

    client_secret=$(curl -sf "$kc_url/admin/realms/$REALM/clients/$client_uuid/client-secret" \
        -H "Authorization: Bearer $token" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

    ok "Client secret retrieved"

    # Update syfter OAuth proxy secret
    info "Updating syfter OAuth proxy secret..."
    local cookie_secret
    cookie_secret=$(openssl rand -hex 16)
    oc create secret generic syfter-oauth-proxy \
        --from-literal=cookie-secret="$cookie_secret" \
        --from-literal=client-secret="$client_secret" \
        -n "$NAMESPACE" --dry-run=client -o yaml | oc apply -f -
    ok "OAuth proxy secret updated"

    echo ""
    echo "$client_secret" > "$SCRIPT_DIR/.client-secret"
    echo "$kc_url" > "$SCRIPT_DIR/.keycloak-url"
}

# ─── Step 5: Update syfter deployment for OIDC ────────────────────────────────

update_syfter_deployment() {
    local kc_url
    kc_url=$(get_kc_url)

    info "Patching syfter-api deployment for OIDC..."

    # Patch the oauth-proxy container args to use OIDC instead of OpenShift
    oc patch deployment syfter-api -n "$NAMESPACE" --type=json -p "[
        {\"op\": \"replace\", \"path\": \"/spec/template/spec/containers/0/args\", \"value\": [
            \"--https-address=:4443\",
            \"--provider=oidc\",
            \"--oidc-issuer-url=$kc_url/realms/$REALM\",
            \"--client-id=$CLIENT_ID\",
            \"--client-secret-file=/etc/oauth-proxy/client-secret\",
            \"--upstream=http://localhost:8000\",
            \"--tls-cert=/etc/tls/private/tls.crt\",
            \"--tls-key=/etc/tls/private/tls.key\",
            \"--cookie-secret-file=/etc/oauth-proxy/cookie-secret\",
            \"--cookie-secure=true\",
            \"--pass-basic-auth=false\",
            \"--pass-access-token=true\",
            \"--skip-auth-regex=^/health$\",
            \"--email-domain=*\",
            \"--insecure-oidc-allow-unverified-email=true\",
            \"--ssl-insecure-skip-verify=true\"
        ]}
    ]"

    ok "Syfter deployment patched for OIDC"
    info "Waiting for rollout..."
    oc rollout status deployment/syfter-api -n "$NAMESPACE" --timeout=120s
    ok "Syfter API restarted with Keycloak OIDC"
}

# ─── Deploy (full flow) ───────────────────────────────────────────────────────

cmd_deploy() {
    check_logged_in

    echo "==========================================="
    echo "  Keycloak Deployment for Syfter"
    echo "==========================================="
    echo ""

    # Generate passwords
    local kc_db_password kc_admin_password
    kc_db_password=$(openssl rand -base64 24)
    kc_admin_password=$(openssl rand -base64 16)

    # Save credentials locally
    cat > "$CREDS_FILE" <<CREDS
KC_ADMIN_PASSWORD=$kc_admin_password
KC_DB_PASSWORD=$kc_db_password
CREDS
    chmod 600 "$CREDS_FILE"

    create_database "$kc_db_password"
    create_secrets "$kc_db_password" "$kc_admin_password"
    deploy_keycloak
    configure_keycloak
    update_syfter_deployment

    local kc_url
    kc_url=$(get_kc_url)

    echo ""
    echo "==========================================="
    echo "  Setup Complete!"
    echo "==========================================="
    echo ""
    echo "Keycloak Admin Console:"
    echo "  URL:      $kc_url/admin"
    echo "  Username: admin"
    echo "  Password: $kc_admin_password"
    echo ""
    echo "OIDC Issuer URL:"
    echo "  $kc_url/realms/$REALM"
    echo ""
    echo "Syfter Browser Access:"
    echo "  https://$(get_syfter_route)"
    echo "  → Redirects to Keycloak login"
    echo ""
    echo "Syfter CLI Access (unchanged):"
    echo "  Uses API keys via X-API-Key header on port 8080"
    echo ""
    echo "Create a user to log in:"
    echo "  $0 create-user"
    echo ""
    echo "Credentials saved to: $CREDS_FILE"
    echo "SAVE THE ADMIN PASSWORD — it cannot be recovered."
}

# ─── Create User ───────────────────────────────────────────────────────────────

cmd_create_user() {
    check_logged_in

    local kc_url kc_admin_password token
    kc_url=$(get_kc_url)
    kc_admin_password=$(get_admin_password)
    token=$(get_admin_token "$kc_url" "$kc_admin_password")

    read -rp "Email address: " email
    read -rp "First name: " first_name
    read -rp "Last name: " last_name
    read -rsp "Password: " password
    echo ""

    local user_status
    user_status=$(curl -s -o /dev/null -w '%{http_code}' \
        "$kc_url/admin/realms/$REALM/users" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "{
            \"email\": \"$email\",
            \"username\": \"$email\",
            \"firstName\": \"$first_name\",
            \"lastName\": \"$last_name\",
            \"enabled\": true,
            \"emailVerified\": true,
            \"credentials\": [{
                \"type\": \"password\",
                \"value\": \"$password\",
                \"temporary\": false
            }]
        }")

    if [[ "$user_status" == "201" ]]; then
        ok "User $email created"
    elif [[ "$user_status" == "409" ]]; then
        ok "User $email already exists"
    else
        fail "Failed to create user (HTTP $user_status)"
    fi
}

# ─── Status ────────────────────────────────────────────────────────────────────

cmd_status() {
    check_logged_in
    echo "Keycloak pods:"
    oc get pods -n "$NAMESPACE" -l app=keycloak
    echo ""
    echo "Route:"
    oc get route keycloak -n "$NAMESPACE" 2>/dev/null || echo "  Not deployed"
    echo ""
    local kc_url
    kc_url=$(get_kc_url 2>/dev/null) || { echo "Keycloak not deployed"; return; }
    echo "Health: $(curl -sf "$kc_url/health/ready" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unreachable")"
    echo ""
    echo "Syfter OAuth proxy provider:"
    oc get deployment syfter-api -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].args}' | python3 -c "
import sys,json
args = json.load(sys.stdin)
for a in args:
    if 'provider' in a or 'issuer' in a:
        print(f'  {a}')
" 2>/dev/null || echo "  Could not determine"
}

# ─── Teardown ──────────────────────────────────────────────────────────────────

cmd_teardown() {
    check_logged_in
    echo "This will remove Keycloak and revert syfter to OpenShift OAuth."
    read -rp "Continue? [y/N] " confirm
    [[ "$confirm" =~ ^[yY]$ ]] || exit 0

    info "Reverting syfter deployment to OpenShift OAuth..."
    oc patch deployment syfter-api -n "$NAMESPACE" --type=json -p "[
        {\"op\": \"replace\", \"path\": \"/spec/template/spec/containers/0/args\", \"value\": [
            \"--https-address=:4443\",
            \"--provider=openshift\",
            \"--openshift-service-account=syfter-api\",
            \"--upstream=http://localhost:8000\",
            \"--tls-cert=/etc/tls/private/tls.crt\",
            \"--tls-key=/etc/tls/private/tls.key\",
            \"--cookie-secret-file=/etc/oauth-proxy/cookie-secret\",
            \"--pass-basic-auth=false\",
            \"--pass-access-token=true\",
            \"--skip-auth-regex=^/health$\",
            \"--openshift-sar={\\\"resource\\\":\\\"services\\\",\\\"verb\\\":\\\"get\\\",\\\"namespace\\\":\\\"syfter\\\"}\"
        ]}
    ]" 2>/dev/null || true

    info "Deleting Keycloak resources..."
    oc delete deployment keycloak -n "$NAMESPACE" 2>/dev/null || true
    oc delete service keycloak -n "$NAMESPACE" 2>/dev/null || true
    oc delete route keycloak -n "$NAMESPACE" 2>/dev/null || true
    oc delete networkpolicy keycloak -n "$NAMESPACE" 2>/dev/null || true
    oc delete secret keycloak-credentials -n "$NAMESPACE" 2>/dev/null || true

    info "Dropping keycloak database..."
    local pg_pod
    pg_pod=$(oc get pod -n "$NAMESPACE" -l app=syfter-db -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [[ -n "$pg_pod" ]]; then
        oc exec -n "$NAMESPACE" "$pg_pod" -- psql -U syfter -d syfter -c "DROP DATABASE IF EXISTS keycloak;" 2>/dev/null || true
    fi

    rm -f "$CREDS_FILE" "$SCRIPT_DIR/.client-secret" "$SCRIPT_DIR/.keycloak-url"
    ok "Keycloak removed"
}

# ─── Main ──────────────────────────────────────────────────────────────────────

case "${1:-}" in
    deploy)      cmd_deploy ;;
    status)      cmd_status ;;
    create-user) cmd_create_user ;;
    teardown)    cmd_teardown ;;
    *)
        echo "Usage: $0 {deploy|status|create-user|teardown}"
        echo ""
        echo "  deploy       Deploy Keycloak and configure OIDC for syfter"
        echo "  status       Check Keycloak health and configuration"
        echo "  create-user  Create a user in the syfter realm"
        echo "  teardown     Remove Keycloak and revert to OpenShift OAuth"
        exit 1
        ;;
esac
