#!/bin/dash
# Created by @jfersec
# Version 0.2
# Decription: This script will
# 1. parse and generate a list of top 20 visitors from apache logs, both historic and recent
# 2. Run geoiplookup to identify countries
# 3. It will then parse apache logs again for 301 and 404 errors
# 4. Generate a list of ips and how many times they caused these http codes
# 5. If actions are over 100 for each ip, they become blocked.
# 6. It also runs whois to show you who you are about to block.
# 7. Parse admin email from whois and send emails to abuse contact, once, with relevant information to support claim.
# 8. Keep a list of emails sent before to prevent spamming over similar issues.
# 9. Send email to recipient with abuse contact and sterile-evidence of actions for forwarding, evaluation.
# Todo: Previous emails sent when blocked ip matches subnet, abuse POC from before. Shows persistence of action despite blocks. 

# set TimeZone information and date output format"
TZ=America/New_York date
TDATE=`date +%Y.%m.%d`

# Set Recipient mail for alerts
RMAIL=recipient-email@mail

# Whitelist ip's to never block
WHITELIST="ip1\|ip2\|ip3"


# Section for File Rotations Functions
rotateTop20 () {
if [ -e top20.txt ]; then
        mv top20.txt top20-$TDATE.txt
else
        continue
fi
}

rotateWPConfig () {
if [ -e autobans.txt ]; then
        mv autobans.txt autobans-$TDATE.txt
else
        continue
fi
}

# Section for precheck settings
ipset_params="hash:ip --netmask 24 --hashsize 64"
CURRENTRULES=$(iptables-save)
IPSETLISTS=$(ipset list -n)

# which geoiplookup, ipset, iptables, etc
preChecksipset () {
#check for existing ipset list names
if echo $IPSETLISTS |grep -q "apache-brute"; then
        continue
else
        ipset create apache-brute $ipset_params
fi
}
#check for existing iptable rule
preChecksiptables () {
if echo $CURRENTRULES | grep -q "apache-brute"; then
        continue
else
        iptables -I INPUT -m set --match-set apache-brute src -j DROP
fi
}
geoCheck () {
#check for geoip
hash geoiplookup 2>/dev/null || { echo >&2 "no geoiplookup not found, exiting, re-run script after succesful install" ;exit; }
}

# Section for first time run settings

isFirstTime () {
if [ ! -e auto-wp-bans-past.txt ] && [ ! -e top20-past.txt ] ; then
        return 0
else
        return 1
fi
}

autoWPConfigPast () {
echo "Top Visitors that requested wp-config from the Past"
zgrep -i "wp-config.php" /var/log/apache2/access.log* | awk -F ":| - " '{print $2}' | sort | uniq > auto-wp-bans-past.txt
while read ip; do
        ipset add apache-brute $ip
done < auto-wp-bans-past.txt
}

Top20Past () {
echo "Top Visitors by Country from the Past"
zgrep -v dummy /var/log/apache2/access.* | grep -v "$WHITELIST" |awk -F ":\|\ -" '{print $2}' 2>/dev/null | sort | uniq -c | sort -rn | head -20 | awk -F " " '{print $2}' > top20-past.txt; while read line; do echo $line `geoiplookup $line`; done < top20-past.txt
}

TopBrutePast () {

echo "Top Brute-Forces by IP from the Past"
while read line; do
        counter=$(zgrep $line /var/log/apache2/access.* | grep "301\|404" | wc -l)
        echo "Found" $line "has made at least" $counter "bad actions, let me see if over 100"
        if [ $counter -gt 100 ]
        then
                echo "Oh yeah, bad visitor, time out bro"
				# check arin abuse contact and email evidence
                ABUSEPOC=$(whois -H $line | grep "abuse-mailbox\|OrgAbuseEmail"| awk -F ":" '{print $2}')
                if grep -q "$ABUSEPOC" previous-abuses.txt; then
                        echo "User continues to persist despite previous attempts $line from other ips $ABUSEPOC" | mail -s "Continued brute-force" $RMAIL
                else
                        echo "A user from your network has committed $counter brute force attempts against us on $TDATE . Please investigate $ABUSEPOC" | mail -s "Brute-Force attempts on our server from $line" $RMAIL
                
                        ipset add apache-brute $line
                        echo "$ABUSEPOC,$line,$counter,$TDATE" >> previous-abuses.txt
                fi
        fi
done < top20-past.txt
}

# Section for consecutive runs
currentautoWPConfig () {
echo "Top Visitors that requested wp-config"
grep -i "wp-config.php" /var/log/apache2/access.log | awk -F " " '{print $1}' | sort | uniq > auto-wp-bans.txt
while read ip; do
        ipset add apache-brute $ip
done < auto-wp-bans.txt
}

currentTop20 () {
echo "Current Top Visitors by Country"
grep -v dummy /var/log/apache2/access.log | grep -v "$WHITELIST" |awk -F " -" '{print $1}' 2>/dev/null | sort | uniq -c | sort -rn | head -20 | awk -F " " '{print $2}' > top20.txt; while read line; do echo $line `geoiplookup $line`; done < top20.txt
}

currentBrute () {
echo "Top Brute-Forces by IP"
while read line; do
        counter=$(grep $line /var/log/apache2/access.log | grep "301\|404" | wc -l)
        echo "Found" $line "has made at least" $counter "bad actions, let me see if over 100"
        if [ $counter -gt 100 ]
        then
                echo "Oh yeah, bad visitor, time out bro"
				# check arin abuse contact and email evidence
                ABUSEPOC=$(whois -H $line | grep "abuse-mailbox\|OrgAbuseEmail"| awk -F ":" '{print $2}')
                if grep -q "$ABUSEPOC,$line" previous-abuses.txt; then
                        continue
                        #echo "User continues to persist despite previous attempts $line from other ips $ABUSEPOC" | mail -s "Continued brute-force" $RMAIL
                else
                        echo "A user from your network has committed $counter brute force attempts against us on $TDATE . Please investigate $ABUSEPOC" | mail -s "Brute-Force attempts on our server from $line" $RMAIL
                
                        ipset add apache-brute $line
                        echo "$ABUSEPOC,$line,$counter,$TDATE" >> previous-abuses.txt
                fi
        fi
done < top20.txt
}

# execute fucntions
geoCheck
preChecksipset
preChecksiptables
rotateTop20
rotateWPConfig

# Check for previous runs, if not, run previous first, re-run and should only run currents
if isFirstTime;
then
        autoWPConfigPast
        Top20Past
        TopBrutePast
else

        currentautoWPConfig
        currentTop20
        currentBrute
fi
