#!/bin/bash
# Created by @jfersec
# Todo: Re-test from scratch
# Updated Sep 30,2019
# Version 0.7a
# Decription: This script will
# 1. parse and generate a list of top 20 visitors from apache logs
# 2. Run geoiplookup to identify country
# 3. It will then parse apache logs again for 301 and 404 errors
# 4. Generate a list of ips and how many times they caused these http codes
# 5. If actions are over 100 for each ip, they become blocked.
# 6. It also runs whois to show you who you are about to block.
# 7. Parse admin email from whois and send emails to abuse contact, once, with relevant information to support claim.
# 8. Keep a list of emails sent before to prevent spamming over similar issues
# Todo: Functions, first run, re-set to last access vs all logs.
# Bans brute force on protected directories via multiple 401's
# Changed hash table to /32 instead of /24
# Aggregate logs better, into a folder or something
# Removed 301 for now
# Needs parallel rewrite for faster performance
# suspect not working due to lack of emails....
# Odds are, simply grouping top20 list of visitors fails when attacker pads visits and attacks/scans are split
# Works behind ELB
# Last edit, had to change log format, thus historical search is now removed.
# Added some dup checks for previous blocks.
# LAST Edit, make Ipv6 workable.

# Credits for IPV6 https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses / David M. Syzdek

# set TimeZone information and date output format"
TZ=America/New_York date
TDATE=$(date +'%Y-%m-%d %H:%M:%S')

# Set Recipient mail for alerts
RMAIL=email@addr

# Whitelist ip's to never block 
# TODO
WHITELIST=""
IPV4="([0-9]{1,3}[\.]){3}[0-9]{1,3}"
IPV6="(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
ELBPRIVATE="(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)"

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
ipset_params="hash:ip --netmask 32 --hashsize 64"
#ipsetv6_params="hash:ip family inet6"
ipsetv6_params="hash:net family inet6"
CURRENTRULES=$(iptables-save)
CURRENTRULES6=$(ip6tables-save)
IPSETLISTS=$(ipset list -n)

# which geoiplookup, ipset, iptables, etc
preChecksipset () {
#check for existing ipset list names
if echo $IPSETLISTS |grep -q "apache-brute"; then
	continue
else
	ipset create apache-brute $ipset_params
fi

if echo $IPSETLISTS |grep -q "apache-brute-v6"; then
	continue
else
	ipset create apache-brute-v6 $ipsetv6_params
fi
}
#check for existing iptable rule
preChecksiptables () {
if echo $CURRENTRULES | grep -q "apache-brute"; then
	continue
else
	iptables -I INPUT -m set --match-set apache-brute src -j DROP
fi

if echo $CURRENTRULES6 | grep -q "apache-brute-v6"; then
	continue
else
	ip6tables -I INPUT -m set --match-set apache-brute-v6 src -j DROP
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

#Removed for now
autoWPConfigPast () {
echo "Top Visitors that requested wp-config from the Past"
zgrep --no-filename -i "wp-config.php" /var/log/apache2/access.log* | awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $1 "," $2}' | sed 's/^-//g' | sed 's/$/,/g' | awk -F "," '{print $1}'  | sort | uniq | grep -v "$WHITELIST" > auto-wp-bans-past.txt
#zgrep -i "wp-config.php" /var/log/apache2/access.log* | awk -F ":| - " '{print $2}' | sort | uniq > auto-wp-bans-past.txt
while read ip; do
	ipset add apache-brute $ip
done < auto-wp-bans-past.txt
cat auto-wp-bans-past.txt
}

#Removed for now
Top20Past () {
echo "Top Visitors by Country from the Past"
zgrep --no-filename -v dummy /var/log/apache2/access.* | awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $1 "," $2 , "," $7 , "," $8}' | grep -v "/aws.alive HTTP" | sed 's/^-//g' |  grep -v "$WHITELIST" |  sort | sed '/^-,//g' |  sed "s/\[CHR\(0\)\]\'\"\`//g" | uniq -c | sort -rn | head -20 | awk -F " " '{print $2}' > top20-past.txt; while read line; do echo $line `geoiplookup $line`; done < top20-past.txt
#zgrep --no-filename -v dummy /var/log/apache2/access.* | awk -F ":\|\ -" '{print $2}' 2>/dev/null | grep -v "$WHITELIST" | sort | uniq -c | sort -rn | head -20 | awk -F " " '{print $2}' > top20-past.txt; while read line; do echo $line `geoiplookup $line`; done < top20-past.txt
}

#Removed for now
TopBrutePast () {

echo "Top Brute-Forces by IP from the Past"
while read line; do
	#awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $7}'
	counter=$(zgrep --no-filename $line /var/log/apache2/access.* |  awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $1 "," $2}' | sed 's/^-,//g' | sed 's/$/,/g' | grep -v "$WHITELIST" | sed "s/,//g" | sed "s/\[CHR\(0\)\]\'\"\`//g"| awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $6 " " $7}' | grep " 403\| 404\| 401")
        #counter=$(zgrep $line /var/log/apache2/access.* | grep " 403 \| 404 \| 401 " | wc -l)
        echo "Found" $line "has made at least" $counter "bad actions, let me see if over 10"
        if [[ $( echo "$counter" | wc -l) -gt 10 ]]
        then
                echo "Bad visitor, time out"
		counterSum=$( echo "$counter" | wc -l)
                ABUSEPOC=$(whois -H $line | grep "abuse-mailbox\|OrgAbuseEmail"| awk -F ":" '{print $2}')
		ipSubnet=$(echo "$line" | cut -d"." -f1,2,3)
		if grep -q "$ABUSEPOC,$ipSubnet" previous-abuses.txt; then
			echo "User continues to persist despite previous attempts $line from other ips $ABUSEPOC" | mail -s "Continued brute-force" $RMAIL
		else
			echo "A user from your network has committed $counterSum brute force attempts against us on $TDATE . Please investigate $ABUSEPOC." "$counter" | mail -s "Brute-Force attempts on our server from $line" $RMAIL
		# check arin abuse contact and email evidence
			ipset add apache-brute $line
			echo "$ABUSEPOC,$line,$counterSum,$TDATE" >> previous-abuses.txt
		fi
        fi
done < top20-past.txt
}

# Section for consecutive runs
#Fixed
currentautoWPConfig () {
echo "Top Visitors that requested wp-config"
grep -i "wp-config.php" /var/log/apache2/access.log | awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $1 "," $2}' | sed 's/^-,//g' | sed 's/$/,/g' | grep -v "$WHITELIST" | awk -F "," '{print $1}' | grep -E -v "$ELBPRIVATE"  | grep -E -o "$IPV4" | sort | uniq > auto-wp-bans.txt
while read ip; do
	if [[ $( checkIP "$ip" | grep ipv4) ]]
        then
		ipset add apache-brute $ip
		./deploy-web-acl.sh $ip
        fi
	if [[ $( checkIP "$ip" | grep ipv6) ]]
        then
		ipset add apache-brute-v6 $ip
		./deploy-web-acl.sh $ip
        fi
done < auto-wp-bans.txt
cat auto-wp-bans.txt
}

#Not needed
currentautoWPConfigv6 () {
echo "Top Visitors that requested wp-config via IPv6"
grep -i "wp-config.php" /var/log/apache2/access.log | awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $1 "," $2}' | sed 's/^-,//g' | sed 's/$/,/g' | grep -v "$WHITELIST" | awk -F "," '{print $1}' | grep -E -v "$ELBPRIVATE"  | grep -E -o "$IPV6" | sort | uniq > auto-wp-bans.txt
while read ip; do
	ipset add apache-brute-v6 $ip
done < auto-wp-bans.txt
cat auto-wp-bans.txt
}


currentTop20 () {
echo "Current Top Visitors by Country"
grep -v dummy /var/log/apache2/access.log |awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $1 "," $2}' | sed 's/^-,//g' | sed 's/$/,/g'| grep -v "$WHITELIST" |awk -F "," '{print $1}' |grep -E -v "$ELBPRIVATE" | sort | uniq -c | sort -rn | head -20 | awk -F " " '{print $2}' > top20.txt; while read line; 
do 
if [[ $( checkIP "$line" | grep ipv4) ]]
then
	echo $line `geoiplookup $line`;
fi
if [[ $( checkIP "$line" | grep ipv6) ]]
then
	echo $line `geoiplookup6 $line`;
fi

done < top20.txt
}


checkIP () {
#Issue here is ipv4, ipv6 entries and log injection attacks to apache logs are 3 unique data sets. All are expected.
local input=$1
#local input=$line
echo "I received this input to validate $input"
if [[ $input =~ $IPV4 ]]
then
	echo "Passed for ipv4"
	return 0

elif [[ $input =~ $IPV6 ]]
then
	echo "Passed for ipv6"
	return 0
else
	echo "Failed checks"
	return 1
fi

}

currentBrute () {
echo "Top Brute-Forces by IP"
while read line; do
        counter=$(grep --no-filename $line /var/log/apache2/access.* | grep -v "$WHITELIST" | awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $6 " " $7}' | grep " 403\| 404\| 401\| 500")
	counterLines=$( echo "$counter" | wc -l)
	#counter=$(grep $line /var/log/apache2/access.log | grep "403\|404\|401" | wc -l)
        echo "Found" $line "has made at least" $counterLines "bad actions, let me see if over 20"
	#if [[ $( echo "$counter" | wc -l) -gt 10 ]
	#if [[ $( checkIP "$line" | grep ipv4) ]]
	if checkIP "$line" | grep ipv4 
	then
		ipset test apache-brute $line
	else
		ipset test apache-brute-v6 $line
	fi
	status=$?
	echo "$status"
	if [ "$status" -ne 0 ] 
	then
		if [ "$counterLines" -gt 10 ]
        	then
               		echo "Bad visitor, time out"
			counterSum=$( echo "$counter" | wc -l)
        	        ABUSEPOC=$(whois -H $line | grep "abuse-mailbox\|OrgAbuseEmail"| awk -F ":" '{print $2}')
			if checkIP "$line" | grep ipv4
		        then
				ipSubnet=$(echo "$line" | cut -d"." -f1,2,3)
			else
				ipSubnet="0.0.0.0"
			fi
			if grep -q "$ipSubnet" previous-abuses.txt; then
				echo "User continues to persist despite previous attempts $line from other ips $ABUSEPOC" | mail -s "Continued brute-force" $RMAIL
				if checkIP "$line" | grep -q 'ipv4'
				then
					ipset add apache-brute $line
					./deploy-web-acl.sh $line
				
				elif checkIP "$line" | grep -q 'ipv6' 
				then
					ipset add apache-brute-v6 $line
					./deploy-web-acl.sh $line
				#echo "User continues to persist despite previous attempts $line from other ips $ABUSEPOC" | mail -s "Continued brute-force" $RMAIL
				else
					
					echo "Reporting some badness $line from ips $ABUSEPOC" | mail -s "Interesting errors here" $RMAIL
				fi
			else
				echo "A user from your network has committed $counterLines brute force attempts against us on $TDATE . Please investigate $ABUSEPOC" "$counter" | mail -s "Brute-Force attempts on our server from $line" $RMAIL
			# check arin abuse contact and email evidence
				if checkIP "$line" | grep -q 'ipv4'
				then
					ipset add apache-brute $line
					./deploy-web-acl.sh $line

				elif checkIP "$line" | grep -q 'ipv6'
				then
					ipset add apache-brute-v6 $line
					./deploy-web-acl.sh $line
				
				fi
				echo "$ABUSEPOC,$line,$counterSum,$TDATE" >> previous-abuses.txt
			fi
		fi
        fi
done < top20.txt
}
#Remove
currentSneaks () {
echo "Indexing previous fails into groups by IP's"
# Find errors, generate list of ips
IPS=$(grep --no-filename " 403 \| 404 \| 401 " /var/log/apache2/access.* | grep -v "$WHITELIST" | awk '{print $1}' | sort | uniq )
# Good but needs full re-write
# So, needs checks for already blocked right?
#IPCOUNT=$(grep --no-filename "$IPS" /var/log/apache2/access.* | awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $1 "," $7}' | grep "403\|404\|401" | sort | uniq -c | sort -nr)
for ips in $IPS; do
IPCOUNT=$(grep --no-filename "$ips" /var/log/apache2/access.* | grep -v "$WHITELIST" | awk -vFPAT='([^ ]*)|("[^"]+")' -vOFS= '{print $7}' | grep "403\|404\|401" | wc -l)
if [ $IPCOUNT -gt 10 ]
        then
		if ipset -T apache-brute "$ips"; then
			echo "IP Already blocked"
		else
	                echo "Oh yeah, bad visitor sneaks, time out bro $ips"
                	ABUSEPOC=$(whois -H $ips | grep "abuse-mailbox\|OrgAbuseEmail"| awk -F ":" '{print $2}')
	                if grep -q "$ips" previous-abuses.txt; then
                        #continue
        	                echo "User continues to persist despite previous attempts $ips from other ips $ABUSEPOC" | mail -s "Continued brute-force $ips" $RMAIL
                	else
                        	echo "A user from your network has committed $IPCOUNT brute force attempts against us on $TDATE . Please investigate $ABUSEPOC" | mail -s "Brute-Force attempts on our server from $ips" $RMAIL
                # check arin abuse contact and email evidence
	                        ipset add apache-brute $ips
        	                echo "$ABUSEPOC,$ips,$IPCOUNT,$TDATE" >> previous-abuses.txt
                	fi
        	fi
	fi
done
}
# execute functions
geoCheck
preChecksipset
preChecksiptables
rotateTop20
rotateWPConfig

# Check for previous runs, if not, run previous first, re-run and should only run currents
if isFirstTime; 
then
	#autoWPConfigPast
	#Top20Past
	#TopBrutePast
	continue
else
	
	currentautoWPConfig
	currentTop20
	currentBrute
	#currentSneaks
fi