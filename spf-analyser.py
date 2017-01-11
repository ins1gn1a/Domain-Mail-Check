#!/usr/bin/env python3

import dns.resolver
import argparse

parser = argparse.ArgumentParser(description='SPF Analyser')
parser.add_argument('--domain','-d',help='Enter the Domain name to veriify. E.g. ins1gn1a.com',required=True)
args = parser.parse_args()

spf_record = False

txt_list = []
for txt in dns.resolver.query(args.domain,'TXT').response.answer:
    txt_list.append(txt.to_text())


txt_list = txt_list[0].split('\n')

for x in txt_list:
    if "v=spf" in x.lower():
        spf_record = x

allowed_servers = spf_record.split("include:")[1:]
print ("[*] Domain: " + args.domain)
if spf_record:
    print ("    [+] SPF: " + spf_record.split("TXT ")[1])
    if "-all" in spf_record:
        print ("\t[+] Only the following mail servers are authorised to send mail from the " + args.domain + " domain:")
        for z in allowed_servers:
            print ("\t    - " + z.split(" ")[0])
    elif "~all" in spf_record:
        print ("\t[+] Only the following mail servers are authorised to send mail from the " + args.domain + " domain with a soft-fail for non-authorised servers, however '~all' should only be used as a transition to '-all':")
        for z in allowed_servers:
            print ("\t    - " + z.split(" ")[0])
    else:
        print ("\t[!] The " + args.domain + " domain is configured in a way that would allow domain email spoofing to be performed.")
else:
    print ("\t[!] The " + args.domain + " domain does not utilise SPF records for authorising mail servers and is vulnerable to domain email spoofing.")
        
