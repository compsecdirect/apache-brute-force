#!/bin/bash
# Version 2
# Updated Mar 7, 2023
# Author: jfersec
# Code taken Darshil Shah from https://stackoverflow.com/questions/62569436/how-to-add-one-ip-in-ip-set-using-aws-wafv2-cli

# Specify intended block usage for this script for individual ip addresses
source config.sh
IP=$1
BLOCK=32

# Add recipient for email when block fails
RECIPIENT=""

# Get existing aws waf ip-set
IPSET_RESULT=$(aws wafv2 get-ip-set --name=$WEB_ACL_NAME --scope REGIONAL --id=$IP_SET_ID --region $WEB_ACL_REGION)

# Extract lock token
LOCKTOKEN=$(echo $IPSET_RESULT| jq ".LockToken" | sed 's/"//g')

# Get array of values of existing blocked ips, since we can no longer only add/remove one entry"
ADDRESSES=( $(echo $IPSET_RESULT | jq -r '.IPSet.Addresses[]'))

# Add new ip into array of values
ADDRESSES+=( "${IP}/${BLOCK}" )

# Update ipset
COMMAND_RESULT=$(aws wafv2 update-ip-set --name $WEB_ACL_NAME --scope REGIONAL --region $WEB_ACL_REGION --addresses "${ADDRESSES[@]}" --id $IP_SET_ID --lock-token $LOCKTOKEN 2>&1)
RETURN_CODE=$?
echo "Returned:: $COMMAND_RESULT"
if [ $RETURN_CODE -ne 0 ]; then
  echo "$COMMAND_RESULT" | mail -s "IP Set Error" "$RECIPIENT"
fi
