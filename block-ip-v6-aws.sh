#!/bin/bash
# Version 1
# Updated Mar 7, 2023
# Author: jfersec
# Code taken Darshil Shah from https://stackoverflow.com/questions/62569436/how-to-add-one-ip-in-ip-set-using-aws-wafv2-cli

# Specify intended block usage for this script for individual ipv6 addresses
source config.sh
IP=$1
BLOCK=128

# Add recipient for email when block fails
RECIPIENT=""

# Get existing aws waf ip-set
IPSET_RESULT=$(aws wafv2 get-ip-set --name=$WEB_ACL_V6NAME --scope REGIONAL --id=$IP_SET_ID_IPV6 --region $WEB_ACL_V6REGION)

# Extract lock token
LOCKTOKEN=$(echo $IPSET_RESULT| jq ".LockToken" | sed 's/"//g')

# Get array of values of existing blocked ips, since we can no longer only add/remove one entry"
IPV6_ADDRESSES=( $(echo $IPSET_RESULT | jq -r '.IPSet.Addresses[]'))

# Add new ip into array of values
IPV6_ADDRESSES+=( "${IP}/${BLOCK}" )

# Update ipset
COMMAND_RESULT=$(aws wafv2 update-ip-set --name $WEB_ACL_V6NAME --scope REGIONAL --region $WEB_ACL_V6REGION --addresses "${IPV6_ADDRESSES[@]}" --id $IP_SET_ID_IPV6 --lock-token $LOCKTOKEN 2>&1)
RETURN_CODE=$?
echo "Returned:: $COMMAND_RESULT"
if [ $RETURN_CODE -ne 0 ]; then
  echo "$COMMAND_RESULT" | mail -s "IP Set Error" "$RECIPIENT"
fi