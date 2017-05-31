#!/bin/bash
# Created by @jfersec
# Version 0.2
# Decription: This script will
# 1. parse and generate a list of top 20 visitors from apache logs
# 2. Run geoiplookup to identify country
# 3. It will then parse apache logs again for 301 and 404 errors
# 4. Generate a list of ips and how many times they caused these http codes
# 5. If actions are over 100 for each ip, they become blocked.
# 6. It also runs whois to show you who you are about to block.
# Todo: Parse admin email from whois and send emails to abuse contact, once, with relevant informatino to support claim.
# Pre-usage: set your ip whitelist via "ip\|ip2\|ip3"
# Usage: ./apache-brute.sh
WHITELIST="ip1\|ip2"

echo "Top Visitors by Country"
zgrep -v dummy /var/log/apache2/access.* | grep -v "$WHITELIST" | awk -F ":\|\ -" '{print $2}' 2>/dev/null | sort | uniq -c | sort -rn | head -20 | awk -F " " '{print $2}' > top20.txt; while read line; do echo $line `geoiplookup $line`; done < top20.txt
echo "Top Brute-Forces by IP"
while read line; do
        counter=$(zgrep $line /var/log/apache2/access.* | grep "301\|404" | wc -l)
        echo "Found" $line "has made at least" $counter "bad actions, let me see if over 100"
        if [ $counter -gt 100 ]
        then
                echo "Oh yeah, bad visitor, time out bro"
                whois -H $line
                iptables -A INPUT -p TCP -s $line --destination-port 443 -j DROP
        fi
done < top20.txt
