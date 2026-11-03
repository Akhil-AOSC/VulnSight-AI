#!/usr/bin/env bash
# READ-ONLY preview of what deploying VulnSight AI would create. Changes nothing.
#
#   az login                         # required first: an expired login fails every call
#   az account set --subscription <id-or-name>
#   deploy/azure/whatif.sh <region>  # e.g. westeurope
#
# Uses placeholder image names and a throwaway key: what-if never pulls images or writes secrets, and
# it does not create the resource group (the preview is made at subscription scope).
# Read the whole output. Deploying is a separate command, to be run only after review and approval:
#   az deployment sub create --location <region> --template-file deploy/azure/subscription.bicep --parameters ...
set -euo pipefail

LOCATION="${1:?usage: whatif.sh <azure-region>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

az account show --query "{subscription:name, id:id}" -o table
echo
echo "Running what-if. No changes are made."
az deployment sub what-if \
  --name "vulnsight-whatif-$(date +%s)" \
  --location "$LOCATION" \
  --template-file "$HERE/subscription.bicep" \
  --parameters location="$LOCATION" \
               resourceGroupName=rg-vulnsight-whatif \
               apiImage=example.azurecr.io/vulnsight-api:whatif \
               workerImage=example.azurecr.io/vulnsight-worker:whatif \
               masterKey="what-if-placeholder-not-a-real-key"
