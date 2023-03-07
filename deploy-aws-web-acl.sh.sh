#!/bin/bash
set -e

# Set timezone and get current date
TZ=America/New_York date
TDATE=$(date +'%Y-%m-%d %H:%M:%S')

# Define log file name
LOG_FILE="deploy_${TDATE}.log"

# Create log file or truncate existing one
touch "$LOG_FILE"

# Initialize line number
LINE_NUM=1

# Helper function for logging
log() {
    echo "$(printf '%4s' "$LINE_NUM"). $(date +"%Y-%m-%d %H:%M:%S.%N") $*" | tee -a "$LOG_FILE"
    ((LINE_NUM++))
}

# Load config file enviornmental variables
source config.sh

# Validate IP
IP=$1
if [ $# -ne 1 ]; then
    log "Usage: $0 <IP address>/<CIDR>"
    exit 1
fi

if [[ $IP =~ ^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:3[0-2]|[12]?[0-9]))$ ]]; then
    log "IP version: IPV4"
    IP_VERSION="IPV4"
elif [[ $IP =~ ^((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){6}(?::[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){5}(?:(?::[0-9A-Fa-f]{1,4}){1,2}|:)|(?:[0-9A-Fa-f]{1,4}:){4}(?:(?::[0-9A-Fa-f]{1,4}){1,3}|:)|(?:[0-9A-Fa-f]{1,4}:){3}(?:(?::[0-9A-Fa-f]{1,4}){1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){2}(?:(?::[0-9A-Fa-f]{1,4}){1,5}|:)|(?:[0-9A-Fa-f]{1,4}:)(?:(?::[0-9A-Fa-f]{1,4}){1,6}|:)|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))(\/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9]))?$
 ]]; then
    log "IP version: IPV6"
    IP_VERSION="IPV6"
else
    log "Invalid IP address"
    exit 1
fi

# Check if IP set exists
IP_SETS=$(aws wafv2 --profile $PROFILE_NAME list-ip-sets --scope 'REGIONAL') || exit 1 # Exit if the command returns an error
export IP_SET_ARN=$(echo "$IP_SETS" | jq -r ".IPSets[] | select(.Name == \"$IP_SET_NAME\") | .ARN")
if [ -n "$IP_SET_ARN" ]; then
  log "The IP set '$IP_SET_NAME' exists with ARN '$IP_SET_ARN'."
else
  # Create IP set
  log "The IP set '$IP_SET_NAME' does not exist. Creating now."
  export IP_SET_ARN=$(aws wafv2 --profile $PROFILE_NAME create-ip-set --name "$IP_SET_NAME" --scope $IP_SET_REGION --addresses "$IP" --ip-address-version "IPV4" | jq -r ".Summary.ARN") || exit 1 # Exit if the command returns an error
  log "The IP set '$IP_SET_NAME' has been created with ARN '$IP_SET_ARN'."
fi


# Check if web ACL exists
WEB_ACLS=$(aws wafv2 --profile $PROFILE_NAME list-web-acls --scope 'REGIONAL') || exit 1 # Exit if the command returns an error
export WEB_ACL_ARN=$(echo "$WEB_ACLS" | jq -r ".WebACLs[] | select(.Name == \"$WEB_ACL_NAME\") | .ARN")
if [ -n "$WEB_ACL_ARN" ]; then
  log "The Web ACL '$WEB_ACL_NAME' exists with ARN '$WEB_ACL_ARN'."
else
  # Create web ACL
  log "The web ACL '$WEB_ACL_NAME' does not exist. Creating now."
  WEB_ACL=$(aws wafv2 create-web-acl \
    --profile $PROFILE_NAME \
    --name "$WEB_ACL_NAME" \
    --default-action='{"Block": {}}' \
    --scope $WEB_ACL_REGION \
    --rules '[
    {
      "Name": "Block_IP",
      "Priority": 1,
      "Statement": {
        "IPSetReferenceStatement": {
          "ARN": "'"$IP_SET_ARN"'"
        }
      },
      "Action": {
        "Block": {}
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "'"$WEB_ACL_NAME"'"
      }
    }
  ]' \
    --visibility-config '{"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "'"$WEB_ACL_NAME"'"}'
  ) || { log "Failed to create web ACL"; exit 1; }

  export WEB_ACL_ARN=$(echo "$WEB_ACL" | jq -r ".Summary.ARN")
  export WEB_ACL_ID=$(echo "$WEB_ACL" | jq -r ".Summary.Id")
  log "The web ACL '$WEB_ACL_NAME' has been created with ARN '$WEB_ACL_ARN' and ID '$WEB_ACL_ID'."
fi

# Associate web ACL with resource
log "Trying association of $WEB_ACL_NAME with resource: $RESOURCE_ARN"
# Using 20 because it may take instantly to 3 minutes for Web ACL creation to propogate. Retrys are every 10 seconds. 
max_retries=24
retry_count=0
while [ $retry_count -lt $max_retries ]; do
    set +e
    response_message=$(aws wafv2 associate-web-acl --web-acl-arn "$WEB_ACL_ARN" --resource-arn "$RESOURCE_ARN" --profile $PROFILE_NAME 2>&1 >/dev/null)
    if [[ $response_message == *"WAFUnavailableEntityException"* ]]; then
        (( retry_count++ ))
        log "Failed to associate web ACL with resource ARN: $RESOURCE_ARN (attempt: $retry_count)"
        if [ $retry_count -eq $max_retries ]; then
            log "Max retries reached. Exiting."
            exit 1
        fi
        sleep 10
    else
        break
    fi
done

set -e

if [[ $response_message != "" ]]; then
    log "Error: $response_message"
    exit 1
fi

# Confirm the update
if aws wafv2 --profile $PROFILE_NAME get-web-acl --scope $WEB_ACL_REGION --name $WEB_ACL_NAME --id $WEB_ACL_ID --query "WebACL.Name" --output text | grep -q "$WEB_ACL_NAME"; then
    log "Web ACL has been associated with resource ARN: $RESOURCE_ARN"
else
    log "Failed to associate web ACL with resource ARN: $RESOURCE_ARN"
fi

echo "Done!"