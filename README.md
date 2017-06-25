# Apache Brute

#### Version 0.2
#### Last Changed June 25, 2017
#### Author @jfersec, CompSec Direct 
#### License: MIT
#### TL;DR

Look at apache logs, block visitors generating excessive 301/404 errors, get emails notification of blocks

### Purpose:
1. parse and generate a list of top 20 visitors from apache logs, both historic and recent
 2. Run geoiplookup to identify countries
 3. It will then parse apache logs again for 301 and 404 errors
 4. Generate a list of ips and how many times they caused these http codes
 5. If actions are over 100 for each ip, they become blocked.
 6. It also runs whois to show you who you are about to block.
 7. Parse admin email from whois and send emails to abuse contact, once, with relevant information to support claim.
 8. Keep a list of emails sent before to prevent spamming over similar issues.
 9. Send email to recipient with abuse contact and sterile-evidence of actions for forwarding, evaluation.

##### Todo: 
Previous emails sent when blocked ip matches subnet, abuse POC from before. Shows persistence of action despite blocks. 

#### Explanation
Defending web-resources is very straight-forward. Often, administrators supplement web-server hardening with a WAF, log-parsers, etc.
However, some actions performed by visitors are unwated, and we know they are unwanted. Applications like Fail2Ban are amazing at this, yet it is hard to measure it's effectiveness at first; even beyond proper configuration and tuning.
Because of this, we decided to make a simple dash script to parse out useful derived from apache logs. In this case, the script contains an auto-block action for users that request wpconfig.php.

The first time the script runs, it will parse "ALL" your apache logs and provide a top 20 all-time visitors list.
It will also block excessive 301 and 404 errors from all time. The script will send email alerts, if you have mail-utils or something similar already working on the server. If not, spend time getting value out of email alerting and set this up.

##### Whitelist
You NEED to whitelist a few ips:
1. Your ip
2. The web-servers private/public ip
3. Anything else you determine.
If you dont, you will have to reboot somehow to blow-out iptables/ipset list

##### Geoiplookup
This script gets the Top 20 visitors, remove whitelist ips, and query the geoiplookup service. This gives you a quick layout of the country origin of your top 20 visitors.
Often times, your top 20 visitors shows un-desired web-traffic.

#### Whois
Part of this script compares a counter variable against on ip. If it surpasses the threshold, the ip is queried over whois and the abuse contact, if present, is extracted.
Originally, we wanted to auto-send emails to the abuse contact based on log activity. This is bad for two reasons:
1. The email sends information about the web-server, like internal ips and other information.
2. The email notification at times could flood the inbox and the auto-replies from abuse often require to fill-out a web-form.
Still, you get an email for each ip blocked and the whois contact. 


##### Running interactive over CRON
Running interactive gives better indication of who is getting blocked by seeing the whois output. We could shove this into the email alerts in the future.
Using CRON allows you to make your web-servers defend themselves through automation.
For example, a CRON entry in /etc/cron.d/ could look like this:
```
SHELL=/bin/dash
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin
MAILTO=root
HOME=/root
# Every 1 minute, poll for update to apache
# block list, and update firewall blacklist.
* * * * * root /root/apache-brute-v2.sh &>/dev/null
```

Every minute is ok, but not 100%. Applications like fail2ban use the tail output in some configs to see what is the last request that came in. This makes this script less-responsive to incoming attacks.
In our testing, using something like nikto to pen-test a web-server could generate over 400 actions with default settings before being banned in under a minute.

##### Why 301 errors and 404's?

404 is simple. Often scripts are setup to look to vulnerable files, directories. Visitors that generate too many 404, 100 of them with the default setting on the script, will get added to an ipset list called block. This list in turn is referenced in iptables and blocks the visitor from returning, via the entire subnet of users.
301 is a bit more interesting. If you have an HTTPS site and tools continue to forward http to https, this is another indicator of automated tool use. During testing, we determined that getting blocked by 301's is more difficult that 404's, since 404 is easier to trigger.

##### Why a threshold of 100?
You can change this to whatever you want, but 
1. Users do make mistakes
2. Bots and search engines often have old links that may have changed.
3. A missing image on an existing page can trigger 404's.
So you can block legitimate visitors for any number of reasons if the threshold if too low.

##### When does this rotate?
The script will rotate the Top20.txt on every run. We debated if keeping a renamed file with the time-stamp was useful, so you can modify the TDATE variable and include time-settings if needed.

For example, a while ago we wrote about how going after Wp-Config.php is a quick way to get banned.
[link to Post!]( https://compsecdirect.com/why-going-after-wp-config-is-a-quick-way-to-get-banned/)
Sure enough, automated WordPress scanners and other custom developed scripts look for this, so use it to your advantage to remove the would-be attackers that are not necessarily doing precision targeting.

##### Usage

``` chmod +x; ./apache-brute-v2.sh```

##### Output
```
Top Visitors that requested wp-config
<Results of auto-bans would be here>

Current Top Visitors by Country
x.x.x.x GeoIP Country Edition: CN, China
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: BG, Bulgaria
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: EU, Europe
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: US, United States
x.x.x.x GeoIP Country Edition: FR, France

Top Brute-Forces by IP
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 10 bad actions, let me see if over 100
Found x.x.x.x has made at least 1 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 2 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 1 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 0 bad actions, let me see if over 100
Found x.x.x.x has made at least 2 bad actions, let me see if over 100
```

##### Aren't there better ways to do this?
Sure, but often simple problems have simple solutions. We often find missing gaps in defense by means of web-servers during pen-tests and audits. It is sometimes necessary to have a simple PoC script that shows how easy it to stop "blind" automated vuln-scanning.
This hardly anyway would stop a determined attacker from repeatedly probing from different infrastructure, but it does deter.
We will keep modifying this script to help identify the "determined".

