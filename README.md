# Bro IDS IP-based global whitelist for bro scripts

Description:<br />

A Bro module that manages an IP-based global whitelist configuration file for all your bro scripts. The whitelists are defined on the file globalwhitelist.db. Allow whitelists based-on Source IP(s), Destination IP(s) and Destination Port(s).<br />

Advantages:<br />
<br />
.  Easy to manage whitelists. Whitelists are all configured in one simple file<br />
.  Add and remove items from the whitelist in real-time. No need to restart bro<br />
.  Less changes on bro scripts<br />
.  Avoid accidental errors changing scripts<br />

### First steps ###

mkdir /usr/share/bro/policy/frameworks/globalwhitelist<br />
cd /tmp && git clone https://github.com/rodrigokroll/zeek_globalwhitelist.git<br />
mv zeek_globalwhitelist/* /usr/share/bro/policy/frameworks/globalwhitelist/<br />

### Whitelist configuration file (globalwhitelist.db) ###

The columns are separated by Tab delimiter with the following content:<br />

. name: bro script or rule name you intend to create the whitelist statement. Rules names are unique on the file.<br />
. sIP: Source IP(s) separated by comma<br />
. dIP: Destination IP(s) separated by comma<br />
. dport: Destination Port(s) separated by comma<br />
. specific: Specific condition(s) separated by comma<br />
. debug: Enable debug using T or disable using F<br />

### Specific condition field ###

. Each specific condition declaration has the following format:<br />
-> Source IP:Destination IP:Destination Port<br />
-> Example : 10.30.198.92:10.0.10.2:443/tcp<br />

. Multiple specific conditions are separated by comma:<br />
-> Source IP:Destination IP:Destination Port,Source IP:Destination IP:Destination Port<br />
Example : 10.30.198.92:10.0.10.2:443/tcp,10.30.198.92:10.0.10.5:443/tcp<br />

### globalwhitelist.db example ###

#fields	name	sIP	dIP	dport	specific  debug<br />
External_DNS_query	0.0.0.0	1.1.1.1,8.8.8.8	53/udp	-	T<br />
Multiple_Connections_Attempt	0.0.0.0	1.1.29.1	443/tcp,22/tcp	10.0.0.3:1.1.29.2:80/tcp,10.30.198.92:10.0.10.2:443/tcp,10.0.0.3:10.0.10.190:9200/tcp	F<br />
Torrent_traffic	10.0.0.3	0.0.0.0	0/tcp	- F<br />
Long_Connections	0.0.0.0	192.168.0.10,192.168.0.11	443/tcp,80/tcp	-	F<br />
High_volume_of_emails	172.23.6.43	0.0.0.0	25/tcp	-	F<br />
Ransomware_Detected	0.0.0.0	0.0.0.0	0/tcp	10.0.0.3:192.168.0.1:443/tcp,10.0.0.3:192.168.0.1:444/tcp	T<br />

Line 1 explained:<br />
External_DNS_query	0.0.0.0	1.1.1.1,8.8.8.8	53/udp	-	T<br />

. Create a whitelist for the bro script "External_DNS_query"<br />
. Define ANY source IP to the destination IP 1.1.1.1 and destination IP 8.8.8.8 AND port 53/udp<br />
. Define none (-) specific conditions<br />
. Enable debug. When debug is enable, a log file is created (named whitelist.log), every time the traffic condition is triggered the log is appended for debugging.<br />

Line 2 explained:<br />
Multiple_Connections_Attempt	0.0.0.0	1.1.29.1	443/tcp,22/tcp	10.0.0.3:1.1.29.2:80/tcp,10.30.198.92:10.0.10.2:443/tcp,10.0.0.3:10.0.10.190:9200/tcp	F<br />

. Create a whitelist for the bro script "Multiple_Connections_Attempt"<br />
. Define ANY source IP to the destination IP 1.1.29.1 AND ( port 443/tcp OR port 22/tcp )<br />
. Define the following specific whitelist:<br />
          ->  Source IP 10.0.0.3 AND Destination IP 1.1.29.2 AND port 80/tcp<br />
          ->  Source IP 10.30.198.92 AND Destination IP 10.0.10.2 AND port 443/tcp<br />
          ->  Source IP 10.0.0.3 AND Destination IP 10.0.10.190 AND port 9200/tcp<br />
. Disable debug<br />

### Bro scripts integration ###

In your bro script:<br />

#Call the module globalwhitelist<br />
@load frameworks/globalwhitelist<br />

#Declare the rulename, using exact the same name on the file globalwhitelist.db<br />
local rulename: string = "External_DNS_query";<br />
#Call the function checkwhitelist passing the parameters rule name, c$id$orig_h, c$id$resp_h and c$id$resp_p<br />
 if (!(GlobalWhitelist::checkwhitelist(rulename,c$id$orig_h,c$id$resp_h,c$id$resp_p))) {<br />
        # continue code to trigger your rule<br />
 }<br />
 
#Deploy bro services<br />
broctl deploy<br />

If the function returns False, the script won't proceed because is whitelisted. If returns True, that means is not whitelist.<br />
I'll post a video soon with a demonstration.<br />
