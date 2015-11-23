#!/usr/bin/env python

from os import system, getcwd
from subprocess import call

bad_ip_list = ['http://malc0de.com/bl/IP_Blacklist.txt',
		'http://www.malwaredomainlist.com/hostslist/ip.txt',
		'https://zeustracker.abuse.ch/blocklist.php?download=badips',
		'http://www.spamhaus.org/drop/edrop.txt',
		'http://myip.ms/files/blacklist/csf/latest_blacklist.txt',
		'http://rules.emergingthreats.net/blockrules/compromised-ips.txt',	
		'http://feeds.dshield.org/top10-2.txt',
		'http://www.dshield.org/feeds/topips.txt',
		'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist',
		'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist',]
				
bad_dns_list = ['http://www.joewein.net/dl/bl/dom-bl.txt',
		'http://www.joewein.net/dl/bl/dom-bl-base.txt',
		'http://mirror1.malwaredomains.com/files/immortal_domains.txt',
		'http://mirror1.malwaredomains.com/files/dynamic_dns.txt',
		'https://zeustracker.abuse.ch/blocklist.php?download=baddomains',
		'http://www.malwaredomainlist.com/hostslist/hosts.txt']

#IP blacklists processing
for link in bad_ip_list:
	call(['wget', link, '--directory-prefix=./qradar_blacklists', '--no-check-certificate', '--tries=2', '--continue', '--timestamping', '--timeout=5', '--random-wait', '--no-proxy', '--inet4-only'])
	
system('cat ./qradar_blacklists/* | grep -Eo "^([0-9]{1,3}[\.]){3}[0-9]{1,3}" | uniq --unique --check-chars=15 | sort -n  > bad_IPs.txt')

#DNS blacklists processing
for dns in bad_dns_list:
	call(['wget', dns, '--directory-prefix=./qradar_blacklists' , '--no-check-certificate', '--tries=2', '--continue', '--timestamping', '--timeout=5', '--random-wait', '--no-proxy', '--inet4-only'])

system('cat ./qradar_blacklists/dom-bl.txt | cut -f1 -d ";" > ./qradar_blacklists/bad_DNS.txt')
system('cat ./qradar_blacklists/dom-bl-base.txt | cut -f1 -d ";" >> ./qradar_blacklists/bad_DNS.txt')
system("cat ./qradar_blacklists/hosts.txt | awk  '/127.0.0.1/ { print $2 }'  >> ./qradar_blacklists/bad_DNS.txt")
system('cat ./qradar_blacklists/immortal_domains.txt | grep -i -P "This is a list|^$" -v >> ./qradar_blacklists/bad_DNS.txt')
system('cat ./qradar_blacklists/BOOT | grep -i PRIMARY | cut -f 2 -d " " | grep -i -v -P "ibm\.com" -v >> ./qradar_blacklists/bad_DNS.txt')
system('cat ./qradar_blacklists/dynamic_dns.txt | grep -P -v "^#|^$" | cut -f 1 -s >> ./qradar_blacklists/bad_DNS.txt')
system('cat ./qradar_blacklists/blocklist.php\?download\=baddomains | grep -P -v "^#|^$" >> ./qradar_blacklists/bad_DNS.txt')
system('cat ./qradar_blacklists/bad_DNS.txt | sort -i | uniq --unique > bad_DNS.txt')

system('rm -rf ./qradar_blacklists/*')

#Recreate (purge) Reference Sets
call(['/opt/qradar/bin/ReferenceDataUtil.sh', 'purge', 'Blacklisted IPs'])
call(['/opt/qradar/bin/ReferenceDataUtil.sh', 'purge', 'Blacklisted DNS'])

ip_path = getcwd()+'/bad_IPs.txt'
dns_path = getcwd()+'/bad_DNS.txt'

#Import data to Reference Sets
call(['/opt/qradar/bin/ReferenceSetUtil.sh', 'load', 'Blacklisted IPs' , ip_path ])
call(['/opt/qradar/bin/ReferenceSetUtil.sh', 'load', 'Blacklisted DNS' , dns_path ])