#!/bin/bash
# Setup FAPI 2.0 Client Policies via Keycloak Admin REST API
set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="fapi-demo"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

echo "=== FAPI 2.0 Setup Script ==="
echo "Keycloak URL: $KEYCLOAK_URL"
echo "Realm: $REALM"
echo ""

# Wait for Keycloak to be ready
echo "Waiting for Keycloak to start..."
until curl -sf "$KEYCLOAK_URL/health/ready" > /dev/null 2>&1; do
  echo "  ... waiting"
  sleep 5
done
echo "Keycloak is ready!"
echo ""

# Get admin access token
echo "Getting admin access token..."
TOKEN_RESPONSE=$(curl -sf -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASS" \
  -d "grant_type=password")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || \
  echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: Failed to get admin access token"
  exit 1
fi
echo "Got access token successfully"
echo ""

# Check if realm exists
echo "Checking realm '$REALM'..."
REALM_CHECK=$(curl -sf -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$KEYCLOAK_URL/admin/realms/$REALM")

if [ "$REALM_CHECK" = "200" ]; then
  echo "Realm '$REALM' exists"
else
  echo "WARNING: Realm '$REALM' not found (HTTP $REALM_CHECK). It should have been imported at startup."
  echo "Check that fapi-realm.json is correctly mounted."
  exit 1
fi
echo ""

# Configure Client Policies for FAPI 2.0
echo "Configuring FAPI 2.0 Client Policies..."
POLICIES_JSON='{
  "policies": [
    {
      "name": "fapi-2-policy",
      "description": "FAPI 2.0 Security Profile enforcement for all clients",
      "enabled": true,
      "conditions": [
        {
          "condition": "any-client",
          "configuration": {}
        }
      ],
      "profiles": [
        "fapi-2-security-profile"
      ]
    }
  ]
}'

POLICY_RESULT=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X PUT "$KEYCLOAK_URL/admin/realms/$REALM/client-policies/policies" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$POLICIES_JSON")

if [ "$POLICY_RESULT" = "204" ] || [ "$POLICY_RESULT" = "200" ]; then
  echo "FAPI 2.0 Client Policies configured successfully!"
else
  echo "WARNING: Policy configuration returned HTTP $POLICY_RESULT"
fi
echo ""

# Verify configuration
echo "=== Verification ==="

# Check client policies
echo "Checking client policies..."
curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$KEYCLOAK_URL/admin/realms/$REALM/client-policies/policies" | python3 -m json.tool 2>/dev/null || echo "(install python3 for pretty JSON output)"
echo ""

# Check OIDC well-known
echo "OIDC Discovery endpoint:"
curl -sf "$KEYCLOAK_URL/realms/$REALM/.well-known/openid-configuration" | python3 -m json.tool 2>/dev/null || \
  curl -sf "$KEYCLOAK_URL/realms/$REALM/.well-known/openid-configuration"
echo ""

echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. cd test-client && npm install && npm start"
echo "  2. Open http://localhost:3000 in your browser"
echo "  3. Open http://localhost:3000/inspector for Protocol Inspector"
echo "  4. Keycloak Admin: $KEYCLOAK_URL/admin (admin/admin)"
