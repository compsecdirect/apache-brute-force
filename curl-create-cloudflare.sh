#!/bin/bash
TZ=America/New_York date
TDATE=`date +%Y.%m.%d`
IP=$1

curl -X POST "https://api.cloudflare.com/client/v4/zones/ID_Number/firewall/access_rules/rules"      -H "Authorization: Bearer AUTH_HASH"      -H "Content-Type: application/json"      --data '{"mode":"block","configuration":{"target":"ip","value":"'"$IP"'"},"notes":"This rule is on because of an event that occured on date '$TDATE'"}'
