#!/bin/bash
# irsa-setup.sh — Configure IRSA for syfter ServiceAccount to access S3
#
# Prerequisites:
#   - ROSA HCP cluster is ready
#   - oc is logged in
#   - aws CLI is configured
#
# Usage:
#   ./irsa-setup.sh <cluster-name> <namespace> <bucket-name> <region>

set -euo pipefail

CLUSTER_NAME="${1:?Usage: $0 <cluster-name> <namespace> <bucket-name> <region>}"
NAMESPACE="${2:-syfter}"
BUCKET_NAME="${3:-__S3_BUCKET__}"
REGION="${4:-us-east-1}"
ROLE_NAME="syfter-s3-access"

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Get the OIDC provider from the cluster
OIDC_PROVIDER=$(rosa describe cluster -c "$CLUSTER_NAME" --output json | python3 -c "
import sys, json
d = json.load(sys.stdin)
url = d.get('aws', {}).get('sts', {}).get('oidc_endpoint_url', '')
print(url.replace('https://', ''))
")

if [ -z "$OIDC_PROVIDER" ]; then
  echo "ERROR: Could not determine OIDC provider for cluster $CLUSTER_NAME"
  exit 1
fi

echo "Cluster: $CLUSTER_NAME"
echo "OIDC Provider: $OIDC_PROVIDER"
echo "AWS Account: $AWS_ACCOUNT_ID"
echo "Bucket: $BUCKET_NAME"

# Create the IAM policy
POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${ROLE_NAME}-policy"
if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
  echo "Policy $POLICY_ARN already exists, skipping creation"
else
  aws iam create-policy \
    --policy-name "${ROLE_NAME}-policy" \
    --policy-document file://$(dirname "$0")/bucket-policy.json \
    --description "S3 access for syfter SBOM storage"
  echo "Created policy: $POLICY_ARN"
fi

# Create the trust policy for the role
TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${NAMESPACE}:syfter-api"
        }
      }
    }
  ]
}
EOF
)

# Create or update the IAM role
if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
  echo "Role $ROLE_NAME already exists, updating trust policy"
  aws iam update-assume-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-document "$TRUST_POLICY"
else
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "IRSA role for syfter S3 access"
  echo "Created role: $ROLE_NAME"
fi

# Attach the policy to the role
aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "$POLICY_ARN"
echo "Attached policy to role"

ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}"
echo ""
echo "IRSA setup complete!"
echo "Role ARN: $ROLE_ARN"
echo ""
echo "Now annotate the ServiceAccount in OpenShift:"
echo "  oc -n $NAMESPACE create sa syfter-api"
echo "  oc -n $NAMESPACE annotate sa syfter-api eks.amazonaws.com/role-arn=$ROLE_ARN"
